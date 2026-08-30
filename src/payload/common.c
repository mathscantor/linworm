#define _GNU_SOURCE
#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include "../arch/arch.h"

volatile sig_atomic_t g_running = 0;
pthread_t g_thread;
int g_pipe_fd[2] = {-1, -1};
void *g_self_handle = NULL;

static volatile sig_atomic_t g_signal_shutdown = 0;
static void *(*g_user_thread_func)(void *) = NULL;

/*
 * Async-signal-safe handler. Sets both flags and writes to the self-pipe
 * so that payload_sleep_ms() returns immediately.
 */
void payload_signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    g_signal_shutdown = 1;
    const char byte = 1;
    (void)write(g_pipe_fd[1], &byte, 1);
}

/*
 * Build an architecture-specific shellcode trampoline in an mmap'd page
 * that calls dlclose(handle) twice (to drop both the RTLD_NOLOAD ref and
 * the original injector ref) then pthread_exit(NULL).  Because the
 * trampoline lives in anonymous memory it survives the dlclose unmap.
 */
static void payload_self_unload(void) {
    close(g_pipe_fd[0]);
    close(g_pipe_fd[1]);
    g_pipe_fd[0] = g_pipe_fd[1] = -1;

    void *dlclose_addr = dlsym(RTLD_DEFAULT, "dlclose");
    void *exit_addr    = dlsym(RTLD_DEFAULT, "pthread_exit");
    if (!dlclose_addr || !exit_addr)
        return;

    long page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (page == MAP_FAILED)
        return;

    uint8_t *c = (uint8_t *)page;
    int off = 0;

#if defined(LINWORM_ARCH_X86_64)
    /*
     * x86_64 trampoline (~50 bytes):
     *   and  rsp, -16              ; stack alignment
     *   movabs rbx, <handle>       ; callee-saved
     *   movabs r12, <dlclose>      ; callee-saved
     *   mov  rdi, rbx  / call r12  ; dlclose(handle)  x2
     *   xor  edi, edi
     *   movabs rax, <pthread_exit>
     *   call rax
     */

    /* and rsp, -16 */
    c[off++] = 0x48; c[off++] = 0x83; c[off++] = 0xe4; c[off++] = 0xf0;

    /* movabs rbx, handle */
    c[off++] = 0x48; c[off++] = 0xbb;
    memcpy(&c[off], &g_self_handle, 8); off += 8;

    /* movabs r12, dlclose */
    c[off++] = 0x49; c[off++] = 0xbc;
    memcpy(&c[off], &dlclose_addr, 8); off += 8;

    /* mov rdi, rbx ; call r12 — dlclose #1 */
    c[off++] = 0x48; c[off++] = 0x89; c[off++] = 0xdf;
    c[off++] = 0x41; c[off++] = 0xff; c[off++] = 0xd4;

    /* mov rdi, rbx ; call r12 — dlclose #2 */
    c[off++] = 0x48; c[off++] = 0x89; c[off++] = 0xdf;
    c[off++] = 0x41; c[off++] = 0xff; c[off++] = 0xd4;

    /* xor edi, edi */
    c[off++] = 0x31; c[off++] = 0xff;

    /* movabs rax, pthread_exit ; call rax */
    c[off++] = 0x48; c[off++] = 0xb8;
    memcpy(&c[off], &exit_addr, 8); off += 8;
    c[off++] = 0xff; c[off++] = 0xd0;

#elif defined(LINWORM_ARCH_X86)
    /*
     * x86 (i386) trampoline (~37 bytes):
     *   cdecl: arguments on stack, ebx callee-saved.
     *   and  esp, -16
     *   mov  ebx, <dlclose>
     *   push <handle>  / call ebx          ; dlclose #1
     *   mov  [esp], <handle> / call ebx    ; dlclose #2
     *   mov  dword [esp], 0
     *   mov  eax, <pthread_exit> / call eax
     */
    uint32_t h32 = (uint32_t)(uintptr_t)g_self_handle;
    uint32_t dc32 = (uint32_t)(uintptr_t)dlclose_addr;
    uint32_t ex32 = (uint32_t)(uintptr_t)exit_addr;

    /* and esp, -16 */
    c[off++] = 0x83; c[off++] = 0xe4; c[off++] = 0xf0;

    /* mov ebx, dlclose */
    c[off++] = 0xbb;
    memcpy(&c[off], &dc32, 4); off += 4;

    /* push handle */
    c[off++] = 0x68;
    memcpy(&c[off], &h32, 4); off += 4;

    /* call ebx — dlclose #1 */
    c[off++] = 0xff; c[off++] = 0xd3;

    /* mov dword [esp], handle — reuse stack slot */
    c[off++] = 0xc7; c[off++] = 0x04; c[off++] = 0x24;
    memcpy(&c[off], &h32, 4); off += 4;

    /* call ebx — dlclose #2 */
    c[off++] = 0xff; c[off++] = 0xd3;

    /* mov dword [esp], 0 */
    c[off++] = 0xc7; c[off++] = 0x04; c[off++] = 0x24;
    c[off++] = 0x00; c[off++] = 0x00; c[off++] = 0x00; c[off++] = 0x00;

    /* mov eax, pthread_exit ; call eax */
    c[off++] = 0xb8;
    memcpy(&c[off], &ex32, 4); off += 4;
    c[off++] = 0xff; c[off++] = 0xd0;

#elif defined(LINWORM_ARCH_AARCH64)
    /*
     * aarch64 trampoline (~60 bytes):
     *   Uses ldr Xn, [pc, #off] to load 64-bit values from a literal
     *   pool placed after the code.  x19/x20/x21 are callee-saved.
     *
     *   ldr  x19, [pc, #24]   ; handle        (pool at code+36)
     *   ldr  x20, [pc, #28]   ; dlclose       (pool at code+44)
     *   ldr  x21, [pc, #32]   ; pthread_exit  (pool at code+52)
     *   mov  x0, x19 / blr x20               ; dlclose #1
     *   mov  x0, x19 / blr x20               ; dlclose #2
     *   mov  x0, #0  / blr x21               ; pthread_exit
     *   <literal pool: 3 x 8 bytes>
     */
    uint32_t *w = (uint32_t *)page;
    int wi = 0;

    /* LDR (literal) Xt: 01 011 000 imm19 Rt — offset in 4-byte units */
    w[wi++] = 0x58000013 | (9  << 5);  /* ldr x19, [pc, #36] — 9 words ahead */
    w[wi++] = 0x58000014 | (10 << 5);  /* ldr x20, [pc, #40] — 10 words */
    w[wi++] = 0x58000015 | (11 << 5);  /* ldr x21, [pc, #44] — 11 words */

    w[wi++] = 0xaa1303e0;              /* mov x0, x19 */
    w[wi++] = 0xd63f0280;              /* blr x20 — dlclose #1 */
    w[wi++] = 0xaa1303e0;              /* mov x0, x19 */
    w[wi++] = 0xd63f0280;              /* blr x20 — dlclose #2 */
    w[wi++] = 0xd2800000;              /* mov x0, #0 */
    w[wi++] = 0xd63f02a0;              /* blr x21 — pthread_exit */

    /* literal pool */
    memcpy(&w[wi], &g_self_handle, 8); wi += 2;
    memcpy(&w[wi], &dlclose_addr, 8);  wi += 2;
    memcpy(&w[wi], &exit_addr, 8);     wi += 2;

    off = wi * 4;

#elif defined(LINWORM_ARCH_ARM)
    /*
     * ARM 32-bit trampoline (~48 bytes):
     *   Uses ldr Rn, [pc, #off] with the ARM pipeline offset (PC =
     *   current insn + 8).  r4/r5/r6 are callee-saved.
     *
     *   ldr  r4, [pc, #20]   ; handle        (pool at code+36)
     *   ldr  r5, [pc, #20]   ; dlclose       (pool at code+40)
     *   ldr  r6, [pc, #20]   ; pthread_exit  (pool at code+44)
     *   mov  r0, r4 / blx r5               ; dlclose #1
     *   mov  r0, r4 / blx r5               ; dlclose #2
     *   mov  r0, #0 / blx r6               ; pthread_exit
     *   <literal pool: 3 x 4 bytes>
     */
    uint32_t *w = (uint32_t *)page;
    int wi = 0;
    uint32_t h32 = (uint32_t)(uintptr_t)g_self_handle;
    uint32_t dc32 = (uint32_t)(uintptr_t)dlclose_addr;
    uint32_t ex32 = (uint32_t)(uintptr_t)exit_addr;

    /*
     * LDR Rt, [PC, #imm12]  — ARM encoding: cond 010 P U 0 W 1 Rn Rt imm12
     * With PC (r15) as Rn, the effective address is PC+8+imm12 (ARM pipeline).
     * Instruction at offset wi*4, literal at target offset:
     *   imm12 = target - (wi*4 + 8)
     */
    int pool_base = 9 * 4;  /* 9 instructions = 36 bytes of code */

    /* ldr r4, [pc, #imm12] — handle at pool_base+0 */
    w[wi] = 0xe59f4000 | (pool_base - (wi * 4 + 8)); wi++;
    /* ldr r5, [pc, #imm12] — dlclose at pool_base+4 */
    w[wi] = 0xe59f5000 | (pool_base + 4 - (wi * 4 + 8)); wi++;
    /* ldr r6, [pc, #imm12] — pthread_exit at pool_base+8 */
    w[wi] = 0xe59f6000 | (pool_base + 8 - (wi * 4 + 8)); wi++;

    w[wi++] = 0xe1a00004;              /* mov r0, r4 */
    w[wi++] = 0xe12fff35;              /* blx r5 — dlclose #1 */
    w[wi++] = 0xe1a00004;              /* mov r0, r4 */
    w[wi++] = 0xe12fff35;              /* blx r5 — dlclose #2 */
    w[wi++] = 0xe3a00000;              /* mov r0, #0 */
    w[wi++] = 0xe12fff36;              /* blx r6 — pthread_exit */

    /* literal pool */
    w[wi++] = h32;
    w[wi++] = dc32;
    w[wi++] = ex32;

    off = wi * 4;

#else
    #error "Unsupported architecture for self-unload trampoline"
#endif

    (void)off;
    pthread_detach(pthread_self());
    ((void (*)(void))page)();
}

/*
 * Thread wrapper: runs the user function, then self-unloads if the
 * shutdown was triggered by SIGUSR2.  On normal process exit the
 * wrapper returns and the destructor handles cleanup via payload_stop().
 */
static void *payload_thread_wrapper(void *arg) {
    void *ret = g_user_thread_func(arg);

    if (g_signal_shutdown && g_self_handle)
        payload_self_unload();

    return ret;
}

/*
 * Create the self-pipe, install the SIGUSR2 handler, and acquire
 * a dlopen handle to our own .so for self-unloading.
 * Returns 0 on success, -1 on failure.
 */
int payload_init(void) {
    if (pipe(g_pipe_fd) == -1)
        return -1;

    fcntl(g_pipe_fd[0], F_SETFL, O_NONBLOCK);
    fcntl(g_pipe_fd[1], F_SETFL, O_NONBLOCK);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = payload_signal_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR2, &sa, NULL) == -1) {
        close(g_pipe_fd[0]);
        close(g_pipe_fd[1]);
        g_pipe_fd[0] = g_pipe_fd[1] = -1;
        return -1;
    }

    Dl_info dl_info;
    if (dladdr((void *)payload_init, &dl_info) && dl_info.dli_fname)
        g_self_handle = dlopen(dl_info.dli_fname, RTLD_NOW | RTLD_NOLOAD);

    g_running = 1;
    return 0;
}

/*
 * Spawn the worker thread.  The thread function is wrapped so that
 * self-unloading happens automatically on SIGUSR2.
 * Returns 0 on success, non-zero errno on failure.
 */
int payload_start(void *(*func)(void *)) {
    g_user_thread_func = func;
    return pthread_create(&g_thread, NULL, payload_thread_wrapper, NULL);
}

/*
 * Signal the worker thread to stop and wait for it to finish.
 * Closes the self-pipe.
 */
void payload_stop(void) {
    g_running = 0;
    const char byte = 1;
    (void)write(g_pipe_fd[1], &byte, 1);

    pthread_join(g_thread, NULL);

    close(g_pipe_fd[0]);
    close(g_pipe_fd[1]);
    g_pipe_fd[0] = g_pipe_fd[1] = -1;
}

/* Returns true while the thread should keep running. */
bool payload_running(void) {
    return g_running != 0;
}

/*
 * Sleep for up to `ms` milliseconds, returning early if the
 * shutdown signal fires (the self-pipe becomes readable).
 */
void payload_sleep_ms(int ms) {
    struct pollfd pfd = {
        .fd = g_pipe_fd[0],
        .events = POLLIN,
    };
    poll(&pfd, 1, ms);

    if (pfd.revents & POLLIN) {
        char drain[16];
        while (read(g_pipe_fd[0], drain, sizeof(drain)) > 0)
            ;
    }
}

/*
 * Append a timestamped line to the given log file.
 * Thread-safe: opens/closes per call so no stale handles.
 */
void payload_log(const char *logpath, const char *fmt, ...) {
    FILE *f = fopen(logpath, "a");
    if (!f)
        return;

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(f, "[%s] ", ts);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fputc('\n', f);
    fclose(f);
}
