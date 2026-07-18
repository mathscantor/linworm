#ifndef LINWORM_H
#define LINWORM_H

#include <stddef.h>
#include <stdint.h>

#include "arch/arch.h"

#define LINWORM_VERSION_MAJOR 1
#define LINWORM_VERSION_MINOR 0
#define LINWORM_VERSION_PATCH 0

#define LINWORM_VERSION_STR \
    "v" STRINGIFY(LINWORM_VERSION_MAJOR) "." \
    STRINGIFY(LINWORM_VERSION_MINOR) "." \
    STRINGIFY(LINWORM_VERSION_PATCH)

#define STRINGIFY(x) _STRINGIFY(x)
#define _STRINGIFY(x) #x

static inline size_t align_up_size(size_t x, size_t a) {
    return (x + a - 1) & ~(a - 1);
}

static inline void *align_up_ptr(void *p, size_t a) {
    return (void *)(((uintptr_t)p + a - 1) & ~(uintptr_t)(a - 1));
}

/* Convenience macros */
#define ALIGN_INT(x, a) (align_up_size((size_t)(x), (size_t)(a)))
#define ALIGN_PTR(p, a) (align_up_ptr((void *)(p), (size_t)(a)))
#define ALIGN_LONG(x)    ALIGN_INT((x), sizeof(long))




#endif