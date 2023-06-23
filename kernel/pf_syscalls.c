#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pf_syscalls.h>
#include <linux/syscalls.h>

static bool hash_table_initialized = false;

struct process_info {
    char process_name[TASK_COMM_LEN];
    size_t name_len;
    struct pf_stat pf_stat;
    struct hlist_node hlist;
};

#define PF_HASH_TABLE_BITS 6 // Can be adjusted based on the expected number of tracked processes
static DECLARE_HASHTABLE(process_info_table, PF_HASH_TABLE_BITS);

struct process_info *get_process_info(const char *process_name, size_t name_len) {
    struct process_info *info;
    unsigned int hash_value;

    hash_value = full_name_hash(NULL, process_name, name_len);
    hash_for_each_possible(process_info_table, info, hlist, hash_value) {
        if (strncmp(info->process_name, process_name, name_len) == 0) {
            return info;
        }
    }

    return NULL;
}

bool is_tracked_process(const char *process_name, size_t name_len) {
    struct process_info *process_info;

    // check if global data structure has been initialized
    if (!hash_table_initialized) {
        return false;
    }

    process_info = get_process_info(process_name, name_len);
    return process_info != NULL;
}

struct task_struct *find_task_by_comm(const char *process_name) {
    struct task_struct *task;

    for_each_process(task) {
        if (strcmp(task->comm, process_name) == 0) {
            return task;
        }
    }

    return NULL;
}

void update_process_cow_page_faults(const char *process_name, size_t name_len, unsigned long address) {
    int i;
    struct process_info *process_info;

    process_info = get_process_info(process_name, name_len);

    process_info->pf_stat.cow_page_faults++;

    // Keep track of the number of page faults in a specific VMA
    for (i = 0; i < process_info->pf_stat.nb_vma; i++) {
        if (address >= process_info->pf_stat.vma_list_start[i] && address < process_info->pf_stat.vma_list_end[i]) {
            process_info->pf_stat.vma_fault[i]++;
            break;
        }
    }
}

void update_process_vma(const char *process_name, size_t name_len) {
    struct process_info *process_info;
    struct task_struct *task, *latest_child = NULL;
    struct vm_area_struct *vma;
    int j = 0;

    process_info = get_process_info(process_name, name_len);

    // Find the process by its name
    task = find_task_by_comm(process_name);

    if (task) {

        // Check if the task has children and find the latest child
        if (!list_empty(&task->children)) {
            latest_child = list_last_entry(&task->children, struct task_struct, sibling);
            task = latest_child; // Update the 'task' variable to point to the latest child
        }

        // Clear the previous VMA information
        process_info->pf_stat.nb_vma = 0;
        memset(process_info->pf_stat.vma_list_start, 0, sizeof(process_info->pf_stat.vma_list_start));
        memset(process_info->pf_stat.vma_list_end, 0, sizeof(process_info->pf_stat.vma_list_end));

        // Update the VMA information
        for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
            if (j < MAX_SIZE_PF) {
                process_info->pf_stat.vma_list_start[j] = vma->vm_start;
                process_info->pf_stat.vma_list_end[j] = vma->vm_end;
                process_info->pf_stat.nb_vma++;
                j++;
            } else {
                break;
            }
        }
    }
}

SYSCALL_DEFINE2(pf_set_param, const char __user *, process_name, size_t, name_len) {
    char k_process_name[TASK_COMM_LEN];
    struct process_info *existing_process_info;
    struct process_info *new_process_info;
    unsigned int hash_value;

    // Initialize the hash table if it hasn't been initialized yet
    if (!hash_table_initialized) {
        hash_init(process_info_table);
        hash_table_initialized = true;
    }
    
    // Input validation
    if (!process_name) {
        printk(KERN_ERR "[INFO940][ERROR] process_name is NULL\n");
        return -EINVAL;
    }

    if (name_len <= 0 || name_len > TASK_COMM_LEN) {
        printk(KERN_ERR "[INFO940][ERROR] Invalid process name length\n");
        return -EINVAL;
    }

    // Copy the process name from user space to kernel space
    if (copy_from_user(k_process_name, process_name, name_len)) {
        printk(KERN_ERR "[INFO940][ERROR] Failed to copy process name from user space to kernel space.\n");
        return -EFAULT;
    }
    k_process_name[name_len] = '\0';

    // Check if the process is already being tracked
    existing_process_info = get_process_info(k_process_name, name_len);
    if (existing_process_info) {
        printk(KERN_INFO "[INFO940] Process is already being tracked.\n"); // may not be required
        return 0; // Process is already being tracked
    }

    // Create a new process_info struct for the process
    new_process_info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    if (!new_process_info) {
        printk(KERN_ERR "[INFO940][ERROR] Failed to allocate memory for process_info struct in kernel space.\n");
        return -ENOMEM;
    }

    // Populate the new process_info struct
    strncpy(new_process_info->process_name, k_process_name, name_len);
    new_process_info->name_len = name_len;
    // Initialize other fields as needed, e.g. zero out the pf_stat structure
    memset(&new_process_info->pf_stat, 0, sizeof(struct pf_stat));

    // Add the new process_info struct to the global hash table
    hash_value = full_name_hash(NULL, k_process_name, name_len);
    hash_add(process_info_table, &new_process_info->hlist, hash_value);

    return 0;
}

SYSCALL_DEFINE3(pf_get_info, const char __user *, process_name, size_t, name_len, struct pf_stat __user *, pf) {
    char k_process_name[TASK_COMM_LEN];
    struct process_info *process_info;

    // check if global data structure has been initialized
    if (!hash_table_initialized) {
        printk(KERN_ERR "[INFO940][ERROR] Global data structure has not been initialized\n");
        return -EACCES;
    }

    // Input validation
    if (!process_name) {
        printk(KERN_ERR "[INFO940][ERROR] process_name is NULL\n");
        return -EINVAL;
    }

    if (name_len <= 0 || name_len > TASK_COMM_LEN) {
        printk(KERN_ERR "[INFO940][ERROR] Invalid process name length\n");
        return -EINVAL;
    }
    if (!pf) {
        printk(KERN_ERR "[INFO940][ERROR] pf_stat pointer is NULL\n");
        return -EINVAL;
    }

    // Copy the process name from user space to kernel space
    if (copy_from_user(k_process_name, process_name, name_len)) {
        printk(KERN_ERR "[INFO940][ERROR] Failed to copy process name from user space to kernel space.\n");
        return -EFAULT;
    }
    k_process_name[name_len] = '\0';

    // Find the process_info struct corresponding to the process name
    process_info = get_process_info(k_process_name, name_len);

    if (!process_info) {
        printk(KERN_ERR "[INFO940][ERROR] Failed to find the specified process.\n");
        return -EINVAL; // Process not found
    }

    // Copy the pf_stat structure from kernel space to user space
    if (copy_to_user(pf, &process_info->pf_stat, sizeof(struct pf_stat))) {
        printk(KERN_ERR "[INFO940][ERROR] Failed to copy pf_stat structure from kernel space to user space.\n");
        return -EFAULT;
    }

    return 0;
}

SYSCALL_DEFINE0(pf_cleanup) {
    struct process_info *process_iter;
    struct hlist_node *tmp;
    unsigned int bkt;
    bool cleaned_up = false;

    // Check if global data structure has been initialized
    if (!hash_table_initialized) {
        printk(KERN_ERR "[INFO940][ERROR] Global data structure has not been initialized\n");
        return -EACCES;
    }
    
    // Iterate through the hash table and free each process_info struct
    hash_for_each_safe(process_info_table, bkt, tmp, process_iter, hlist) {
        // Remove the process_info struct from the hash table
        hash_del(&process_iter->hlist);

        // Free the memory allocated for the process_info struct
        kfree(process_iter);

        // Indicate that at least one process_info struct was cleaned up
        cleaned_up = true;

        // In order to reset the entire state of the hash table and start from a clean slate
        hash_table_initialized = false;
    }

    // No process_info structs to clean up
    if (!cleaned_up) {
        printk(KERN_ERR "[INFO940][ERROR] No process_info structs to clean up.\n");
        return -EACCES;
    }

    return 0;
}

