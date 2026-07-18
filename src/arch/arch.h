#ifndef ARCH_ARCH_H
#define ARCH_ARCH_H

#include <stddef.h>
#include <stdint.h>
#include <sys/user.h>

/*
 * Architecture detection.
 * Uses Makefile-provided -D flags with compiler builtins as fallback.
 */
#if defined(X86_64) || defined(__x86_64__)
  #define LINWORM_ARCH_X86_64
#elif defined(X86) || defined(__i386__)
  #define LINWORM_ARCH_X86
#elif defined(AARCH64) || defined(__aarch64__)
  #define LINWORM_ARCH_AARCH64
#elif defined(ARM) || defined(__arm__)
  #define LINWORM_ARCH_ARM
#else
  #error "Unsupported architecture. Define X86_64, X86, AARCH64, or ARM."
#endif

/* --- Register type (unified) --- */

#if defined(LINWORM_ARCH_ARM)
typedef struct user_regs REG;
#else
typedef struct user_regs_struct REG;
#endif

/* --- Word / pointer size on the target --- */

#if defined(LINWORM_ARCH_X86_64) || defined(LINWORM_ARCH_AARCH64)
  #define ARCH_WORD_SIZE 8
#else
  #define ARCH_WORD_SIZE 4
#endif

/* --- Calling convention: max register-passed arguments --- */

#if defined(LINWORM_ARCH_X86_64)
  #define ARCH_MAX_REG_ARGS 6   /* rdi, rsi, rdx, rcx, r8, r9 */
#elif defined(LINWORM_ARCH_X86)
  #define ARCH_MAX_REG_ARGS 0   /* cdecl: all args on stack */
#elif defined(LINWORM_ARCH_AARCH64)
  #define ARCH_MAX_REG_ARGS 8   /* x0-x7 */
#elif defined(LINWORM_ARCH_ARM)
  #define ARCH_MAX_REG_ARGS 4   /* r0-r3 */
#endif

/* --- Arch-agnostic remote-call descriptor --- */

#define CALL_MAX_ARGS 8

typedef struct {
    unsigned long func_addr;
    unsigned long args[CALL_MAX_ARGS];
    int           nargs;
} call_args_t;

/*
 * Per-architecture shellcode blobs.
 *
 * Each blob contains a call trampoline that:
 *   1. (x86 family only) aligns the stack to 16 bytes
 *   2. Calls the function whose address is in the designated register
 *   3. Traps back to the injector (int3 / brk / bkpt)
 *
 * x86_64 additionally includes a lock-cmpxchg trampoline at offset 7
 * for atomic 8-byte patching. The other architectures use
 * load-exclusive/store-exclusive sequences for atomic ops, which are
 * multi-instruction and not included here.
 */

#if defined(LINWORM_ARCH_X86_64)

static const uint8_t ARCH_INJECT_CODE[] = {
    0x48, 0x83, 0xe4, 0xf0, 0xff, 0xd0, 0xcc,        /* and rsp,-16; call rax; int3       */
    0xf0, 0x48, 0x0f, 0xb1, 0x37, 0xcc               /* lock cmpxchg [rdi],rsi; int3      */
};

#elif defined(LINWORM_ARCH_X86)

static const uint8_t ARCH_INJECT_CODE[] = {
    0x83, 0xe4, 0xf0, 0xff, 0xd0, 0xcc,               /* and esp,-16; call eax; int3       */
    0xf0, 0x0f, 0xb1, 0x37, 0xcc                      /* lock cmpxchg [edi],esi; int3      */
};

#elif defined(LINWORM_ARCH_AARCH64)

static const uint8_t ARCH_INJECT_CODE[] = {
    0x00, 0x02, 0x3f, 0xd6,                            /* blr x16                           */
    0x00, 0x00, 0x20, 0xd4                             /* brk #0                            */
};

#elif defined(LINWORM_ARCH_ARM)

static const uint8_t ARCH_INJECT_CODE[] = {
    0x3c, 0xff, 0x2f, 0xe1,                            /* blx r12                           */
    0x70, 0x00, 0x20, 0xe1                             /* bkpt #0                           */
};

#endif

#define ARCH_INJECT_CODE_SIZE sizeof(ARCH_INJECT_CODE)

/* --- Register accessor inline functions --- */

static inline void arch_set_ip(REG *r, unsigned long v) {
#if defined(LINWORM_ARCH_X86_64)
    r->rip = v;
#elif defined(LINWORM_ARCH_X86)
    r->eip = v;
#elif defined(LINWORM_ARCH_AARCH64)
    r->pc = v;
#elif defined(LINWORM_ARCH_ARM)
    r->uregs[15] = v;
#endif
}

static inline void arch_set_sp(REG *r, unsigned long v) {
#if defined(LINWORM_ARCH_X86_64)
    r->rsp = v;
#elif defined(LINWORM_ARCH_X86)
    r->esp = v;
#elif defined(LINWORM_ARCH_AARCH64)
    r->sp = v;
#elif defined(LINWORM_ARCH_ARM)
    r->uregs[13] = v;
#endif
}

static inline unsigned long arch_get_sp(const REG *r) {
#if defined(LINWORM_ARCH_X86_64)
    return r->rsp;
#elif defined(LINWORM_ARCH_X86)
    return r->esp;
#elif defined(LINWORM_ARCH_AARCH64)
    return r->sp;
#elif defined(LINWORM_ARCH_ARM)
    return r->uregs[13];
#endif
}

/* Register that holds the function pointer for the call trampoline. */
static inline void arch_set_func(REG *r, unsigned long v) {
#if defined(LINWORM_ARCH_X86_64)
    r->rax = v;
#elif defined(LINWORM_ARCH_X86)
    r->eax = v;
#elif defined(LINWORM_ARCH_AARCH64)
    r->regs[16] = v;   /* x16 — IP0 scratch */
#elif defined(LINWORM_ARCH_ARM)
    r->uregs[12] = v;  /* r12 — IP scratch  */
#endif
}

static inline unsigned long arch_get_ret(const REG *r) {
#if defined(LINWORM_ARCH_X86_64)
    return r->rax;
#elif defined(LINWORM_ARCH_X86)
    return r->eax;
#elif defined(LINWORM_ARCH_AARCH64)
    return r->regs[0];
#elif defined(LINWORM_ARCH_ARM)
    return r->uregs[0];
#endif
}

static inline void arch_set_reg_arg(REG *r, int n, unsigned long v) {
#if defined(LINWORM_ARCH_X86_64)
    switch (n) {
        case 0: r->rdi = v; break;
        case 1: r->rsi = v; break;
        case 2: r->rdx = v; break;
        case 3: r->rcx = v; break;
        case 4: r->r8  = v; break;
        case 5: r->r9  = v; break;
        default: break;
    }
#elif defined(LINWORM_ARCH_X86)
    (void)r; (void)n; (void)v; /* cdecl: no register arguments */
#elif defined(LINWORM_ARCH_AARCH64)
    if (n >= 0 && n < 8) r->regs[n] = v;
#elif defined(LINWORM_ARCH_ARM)
    if (n >= 0 && n < 4) r->uregs[n] = v;
#endif
}

/*
 * Base address where stack-based overflow arguments should be written.
 * On x86/x86_64 the shellcode does AND SP,-16 before CALL, so args must
 * sit at the aligned position. On ARM/aarch64 BLR/BLX does not touch SP.
 */
static inline unsigned long arch_stack_args_base(const REG *r) {
#if defined(LINWORM_ARCH_X86_64) || defined(LINWORM_ARCH_X86)
    return arch_get_sp(r) & ~0xFUL;
#else
    return arch_get_sp(r);
#endif
}

#endif /* ARCH_ARCH_H */
