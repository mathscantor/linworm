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

#include "../logging/logger.h"

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
void hexdump(const void *data, size_t size);

#endif