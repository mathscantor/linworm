#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging/logger.h"
#include "helpers/common.h"
#include "args/parser.h"
#include "helpers/ptrace.h"

int main(int argc, char *argv[]) {

    int retval = EXIT_SUCCESS;
    
    uint8_t inject_code[] = { 
        0x48, 0x83, 0xe4, 0xf0, 0xff, 0xd0, 0xcc,   // AND RSP, -16; CALL RAX; INT3;
        0xf0, 0x48, 0x0f, 0xb1, 0x37, 0xcc          // LOCK CMPXCHG QWORD PTR [RDI],RSI; INT3;
    };
    
    size_t inject_code_size = ALIGN_LONG(sizeof(inject_code));
    char *orig_code = malloc(inject_code_size);
    char *verify_code = malloc(inject_code_size);
    REG orig_regs = {0};
    long inject_addr = 0;

    long target_malloc_addr = 0;
    long target_free_addr = 0;
    long target_dlopen_addr = 0;

    // GLIBC Version >= 2.34 uses dlopen instead of __libc_dlopen_mode, 
    // Thus, we need to check the version and use the appropriate function name
#if defined(__GLIBC__) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 34)
    char *dlopen_func_name = "dlopen";
#else
    char *dlopen_func_name = "__libc_dlopen_mode";
#endif  

    user_args_t user_args;

    user_args = parse_args(argc, argv);
    logger_init(user_args.oopts_verbose, NULL); 

    log_message(INFO, __func__, "linworm starting to inject into PID %d...", user_args.ropts_target_pid);
    if (!ptrace_attach(user_args.ropts_target_pid)) {
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Successfully attached to target PID %d", user_args.ropts_target_pid);

    // Get the address of the target's executable memory region (first in the /proc/<pid>/maps file with 'x' permission)
    inject_addr = get_target_exec_addr(user_args.ropts_target_pid);
    log_message(INFO, __func__, "Injecting code into target PID %d at address 0x%lx", user_args.ropts_target_pid, inject_addr);

    // Backup original code at the injection address
    if (!ptrace_read(user_args.ropts_target_pid, inject_addr, orig_code, inject_code_size)) {
        log_message(ERROR, __func__, "Failed to read original code from target PID %d", user_args.ropts_target_pid);
        retval = EXIT_FAILURE;
        goto cleanup;
    }

    // Backup original registers (if needed for restoration later)
    if (!ptrace_getregs(user_args.ropts_target_pid, &orig_regs)) {
        log_message(ERROR, __func__, "Failed to get original registers from target PID %d", user_args.ropts_target_pid);
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    
    // Write the injection code to the target process
    if (!ptrace_write(user_args.ropts_target_pid, inject_addr, inject_code, inject_code_size)) {
        log_message(ERROR, __func__, "Failed to write injection code to target PID %d", user_args.ropts_target_pid);
        retval = EXIT_FAILURE;
        goto cleanup;
    }

    // Verify that the injection code was written correctly
    if (!ptrace_read(user_args.ropts_target_pid, inject_addr, verify_code, inject_code_size)) {
        log_message(ERROR, __func__, "Failed to read back injection code from target PID %d", user_args.ropts_target_pid);
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Original code at 0x%lx (size: %zu bytes):", inject_addr, inject_code_size);
    hexdump(orig_code, inject_code_size);
    log_message(INFO, __func__, "Injected code at 0x%lx (size: %zu bytes):", inject_addr, inject_code_size);
    hexdump(verify_code, inject_code_size);

    // Get the addresses of malloc, free, and __libc_dlopen_mode in the target process
    target_malloc_addr = get_target_func_addr(user_args.ropts_target_pid, "malloc");
    if (target_malloc_addr == -1) {
        log_message(ERROR, __func__, "Failed to get target malloc address");
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Target malloc address: 0x%lx", target_malloc_addr);

    target_free_addr = get_target_func_addr(user_args.ropts_target_pid, "free");
    if (target_free_addr == -1) {
        log_message(ERROR, __func__, "Failed to get target free address");
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Target free address: 0x%lx", target_free_addr);

    target_dlopen_addr = get_target_func_addr(user_args.ropts_target_pid, dlopen_func_name);
    if (target_dlopen_addr == -1) {
        log_message(ERROR, __func__, "Failed to get target dlopen address");
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Target dlopen address: 0x%lx", target_dlopen_addr);

    // Load our custom library into the target process
    // TODO

cleanup:
    SAFE_FREE(verify_code);
    SAFE_FREE(orig_code);
    return retval;
}