#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#include "logging/logger.h"
#include "helpers/common.h"
#include "args/parser.h"
#include "helpers/ptrace.h"

int main(int argc, char *argv[]) {

    int retval = EXIT_SUCCESS;
    bool target_attached = false;
    bool code_injected = false;
    
    uint8_t inject_code[ARCH_INJECT_CODE_SIZE];
    memcpy(inject_code, ARCH_INJECT_CODE, ARCH_INJECT_CODE_SIZE);

    size_t inject_code_size = ALIGN_LONG(sizeof(inject_code));
    char *orig_code = malloc(inject_code_size);
    char *verify_code = malloc(inject_code_size);
    REG orig_regs = {0};
    REG regs = {0};
    long inject_addr = 0;
    char *abs_lib_path = NULL;

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

    abs_lib_path = realpath(user_args.ropts_library_path, NULL);
    if (abs_lib_path == NULL) {
        log_message(ERROR, __func__, "Failed to resolve library path '%s': %s", 
                    user_args.ropts_library_path, strerror(errno));
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Resolved library path: %s", abs_lib_path);

    log_message(INFO, __func__, "linworm starting to inject into PID %d...", user_args.ropts_target_pid);
    if (!ptrace_attach(user_args.ropts_target_pid)) {
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    target_attached = true;
    log_message(INFO, __func__, "Successfully attached to target PID %d", user_args.ropts_target_pid);

    // Get the addresses of malloc, free, and dlopen in the target process
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

    // Work on a copy of the original registers
    if (memcpy(&regs, &orig_regs, sizeof(REG)) == NULL) {
        log_message(ERROR, __func__, "Failed to copy original registers");
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    
    // Write the injection code to the target process
    if (!ptrace_write(user_args.ropts_target_pid, inject_addr, inject_code, inject_code_size)) {
        log_message(ERROR, __func__, "Failed to write injection code to target PID %d", user_args.ropts_target_pid);
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    code_injected = true;

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

    // --- Load the library into the target process ---
    size_t path_len = strlen(abs_lib_path) + 1;
    size_t aligned_path_len = ALIGN_LONG(path_len);

    long target_heap_buf = call_target_func(user_args.ropts_target_pid, inject_addr, &regs,
        &(call_args_t){ .func_addr = target_malloc_addr, .args = { aligned_path_len }, .nargs = 1 });
    if (target_heap_buf == 0) {
        log_message(ERROR, __func__, "Target malloc failed (returned NULL)");
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    log_message(INFO, __func__, "Target malloc returned buffer at 0x%lx", target_heap_buf);

    char *path_buf = calloc(1, aligned_path_len);
    memcpy(path_buf, abs_lib_path, path_len);
    if (!ptrace_write(user_args.ropts_target_pid, target_heap_buf, path_buf, aligned_path_len)) {
        log_message(ERROR, __func__, "Failed to write library path to target heap buffer at 0x%lx", target_heap_buf);
        free(path_buf);
        retval = EXIT_FAILURE;
        goto cleanup;
    }
    free(path_buf);

    log_message(INFO, __func__, "Calling dlopen(\"%s\", RTLD_NOW) in target...", abs_lib_path);
    long lib_handle = call_target_func(user_args.ropts_target_pid, inject_addr, &regs,
        &(call_args_t){ .func_addr = target_dlopen_addr, .args = { target_heap_buf, RTLD_NOW }, .nargs = 2 });
    if (lib_handle == 0) {
        log_message(ERROR, __func__, "Target dlopen failed (returned NULL)");
    } else {
        log_message(INFO, __func__, "Library loaded successfully (handle: 0x%lx)", lib_handle);
    }

    call_target_func(user_args.ropts_target_pid, inject_addr, &regs,
        &(call_args_t){ .func_addr = target_free_addr, .args = { target_heap_buf }, .nargs = 1 });
    log_message(INFO, __func__, "Freed target heap buffer containing payload library path at 0x%lx", target_heap_buf);

    if (lib_handle == 0) {
        retval = EXIT_FAILURE;
        goto cleanup;
    }

    log_message(INFO, __func__, "Injection complete! Library loaded in target PID %d", user_args.ropts_target_pid);

cleanup:
    if (code_injected && target_attached) {
        log_message(INFO, __func__, "Restoring target state and detaching...");
        restore_state_and_detach(user_args.ropts_target_pid, inject_addr,
                                 orig_code, (int)inject_code_size, orig_regs);
    } else if (target_attached) {
        log_message(INFO, __func__, "Detaching from target...");
        ptrace_detach(user_args.ropts_target_pid);
    }
    SAFE_FREE(abs_lib_path);
    SAFE_FREE(verify_code);
    SAFE_FREE(orig_code);
    return retval;
}