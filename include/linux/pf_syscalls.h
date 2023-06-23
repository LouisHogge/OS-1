#ifndef _PF_SYSCALLS_H
#define _PF_SYSCALLS_H

#include <linux/types.h>
#include <linux/limits.h>

#define MAX_SIZE_PF 128

struct pf_stat {
    int nb_vma; // Number of VMA of a specific process
    long cow_page_faults; // Number of CoW page faults of a specific process
    long vma_fault[MAX_SIZE_PF]; // Array that contains CoW page faults per VMA
    unsigned long vma_list_start[MAX_SIZE_PF]; // Array that contains the start address of each VMA
    unsigned long vma_list_end[MAX_SIZE_PF]; // Array that contains the end address of each VMA
};

void update_process_vma(const char *process_name, size_t name_len);
void update_process_cow_page_faults(const char *process_name, size_t name_len, unsigned long address);
bool is_tracked_process(const char *process_name, size_t name_len);

#endif /* _PF_SYSCALLS_H */

