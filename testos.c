/*
  Tester program used to test the implementation of the system call.
  Compile your program with following command: gcc -o test test.c

  Usage: ./test -o <operation> -p <process_name> where <operation> is one of
  'set_param', 'get_info' or 'cleanup' and <process_name> is the name of the
  process to monitor.

  You can trace a simple fork program to test your implementation.
*/
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_SIZE 128

/* Do not modify this structure */
struct pf_stat {
  // Number of VMA of a specific process
  int nb_vma;
  // Number of CoW page faults of a specific process
  long cow_page_faults;
  // Array that contains CoW page faults per VMA
  long vma_fault[MAX_SIZE];
  // Array that contains the start address of each VMA
  unsigned long vma_list_start[MAX_SIZE];
  // Array that contains the end address of each VMA
  unsigned long vma_list_end[MAX_SIZE];
};

static void display_pf_stat(struct pf_stat *pf) {
  if (!pf)
    return;

  printf("Number of VMA       : %d\n", pf->nb_vma);
  printf("Number of COW faults: %ld\n", pf->cow_page_faults);
  printf("All VMA:\n");
  for (int i = 0; i < pf->nb_vma; i++) {
    printf(" [%2d]: 0x%lx - 0x%lx (size: 0x%lx): %ld cow faults\n", i,
           pf->vma_list_start[i], pf->vma_list_end[i],
           pf->vma_list_end[i] - pf->vma_list_start[i], pf->vma_fault[i]);
  }
}

static inline long pf_set_param(const char *process_name, size_t name_len) {
  return syscall(385, process_name, name_len);
}

static inline long pf_get_info(const char *process_name, size_t name_len,
                               struct pf_stat *pf) {
  return syscall(386, process_name, name_len, pf);
}

static inline long pf_cleanup() { return syscall(387); }

int main(int argc, char *const *argv) {
  int ch;
  const char *opt = NULL, *process_name = NULL, *val = NULL;
  while ((ch = getopt(argc, argv, "p:o:")) != -1) {
    switch (ch) {
    case 'o':
      opt = optarg;
      break;
    case 'p':
      process_name = optarg;
      break;
    }
  }
  if (!opt) {
    printf("Specify one of operations: 'set_param', 'get_info' or 'cleanup'\n");
    exit(EXIT_FAILURE);
  }

  if (strlen(opt) == strlen("set_param") &&
      !strncmp("set_param", opt, strlen(opt))) {

    if (!process_name) {
      printf("Specify a process to monitor (-p <process_name>).\n");
      exit(EXIT_FAILURE);
    }

    if (pf_set_param(process_name, strlen(process_name)) == 0) {
      printf("pf_set_param performed successfully.\n");
      exit(EXIT_SUCCESS);
    }

    if (errno == ENOSYS) {
      fprintf(stderr, "[ERROR] Syscall not implemented.\n");
      exit(EXIT_FAILURE);
    } else if (errno == EINVAL) {
      fprintf(stderr, "[ERROR] Bad argument value.\n");
      exit(EXIT_FAILURE);
    } else if (errno == ENOMEM) {
      fprintf(stderr, "[ERROR] Failed to allocate kernel memory.\n");
      exit(EXIT_FAILURE);
    }

  } else if (strlen(opt) == strlen("get_info") &&
             !strncmp("get_info", opt, strlen(opt))) {

    if (!process_name) {
      printf("Specify a process to get page fault info (-p <process_name>).\n");
      exit(EXIT_FAILURE);
    }

    // Allocate pf_stat structure and set inner memory to 0
    struct pf_stat *pf = malloc(sizeof(struct pf_stat));
    if (!pf) {
      fprintf(stderr, "[ERROR] failed to allocate memory.\n");
      exit(EXIT_FAILURE);
    }
    memset(pf->vma_fault, 0, MAX_SIZE);
    memset(pf->vma_list_start, 0, MAX_SIZE);
    memset(pf->vma_list_end, 0, MAX_SIZE);

    if (pf_get_info(process_name, strlen(process_name), pf) == 0) {
      display_pf_stat(pf);
      free(pf);
      exit(EXIT_SUCCESS);
    }

    if (errno == ENOSYS) {
      fprintf(stderr, "[ERROR] Syscall not implemented.\n");
    } else if (errno == EACCES) {
      fprintf(stderr, "[ERROR] Kernel data structure not initialized.\n");
    } else if (errno == EINVAL) {
      fprintf(stderr, "[ERROR] Bad argument value.\n");
    } else if (errno == ENOMEM) {
      fprintf(stderr, "[ERROR] Failed to allocate kernel memory.\n");
    }

    free(pf);
    exit(EXIT_FAILURE);

  } else if (strlen(opt) == strlen("cleanup") &&
             !strncmp("cleanup", opt, strlen(opt))) {

    if (pf_cleanup() == 0) {
      printf("pf_cleanup performed successfully.\n");
      exit(EXIT_SUCCESS);
    }

    if (errno == ENOSYS) {
      fprintf(stderr, "[ERROR] Syscall not implemented.\n");
      exit(EXIT_FAILURE);
    } else if (errno == EACCES) {
      fprintf(stderr, "[ERROR] Kernel data structure not initialized.\n");
      exit(EXIT_FAILURE);
    }
  }

  return 0;
}