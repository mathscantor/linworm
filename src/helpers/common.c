#include "common.h"

long get_target_exec_addr(pid_t target_pid) {
    FILE *fp;
    char filename[30];
    char line[850];
    long addr;
    char perms[5];

    sprintf(filename, "/proc/%d/maps", target_pid);
    fp = fopen(filename, "r");

    while (fgets(line, 850, fp) != NULL) {
        sscanf(line, "%lx-%*s %4s %*s %*s %*d", &addr, perms);
        if (strstr(perms, "x") != NULL) {
            break;
        }
    }
    fclose(fp);
    log_message(INFO, __func__, "Found executable address on target: 0x%lx", addr);
    return addr;
}

long call_target_func(pid_t target, long inject_addr, REG *regs,
                      const call_args_t *call) {

    if (call->nargs > CALL_MAX_ARGS) {
        log_message(ERROR, __func__, "Too many arguments (%d, max %d)", call->nargs, CALL_MAX_ARGS);
        return -1;
    }

    arch_set_ip(regs, (unsigned long)inject_addr);
    arch_set_func(regs, call->func_addr);

    int reg_args = (call->nargs < ARCH_MAX_REG_ARGS) ? call->nargs : ARCH_MAX_REG_ARGS;
    for (int i = 0; i < reg_args; i++)
        arch_set_reg_arg(regs, i, call->args[i]);

#if ARCH_MAX_REG_ARGS < CALL_MAX_ARGS
    if (call->nargs > ARCH_MAX_REG_ARGS) {
        unsigned long stack_base = arch_stack_args_base(regs);
        for (int i = ARCH_MAX_REG_ARGS; i < call->nargs; i++) {
            unsigned long val = call->args[i];
            unsigned long offset = (unsigned long)(i - ARCH_MAX_REG_ARGS) * ARCH_WORD_SIZE;
            ptrace_write(target, stack_base + offset, &val, ARCH_WORD_SIZE);
        }
    }
#endif

    if (!ptrace_setregs(target, regs)) {
        log_message(ERROR, __func__, "Failed to set registers for remote call");
        return -1;
    }
    if (!ptrace_cont(target)) {
        log_message(ERROR, __func__, "Remote call did not complete");
        return -1;
    }
    if (!ptrace_getregs(target, regs)) {
        log_message(ERROR, __func__, "Failed to read return value after remote call");
        return -1;
    }
    return arch_get_ret(regs);
}

long get_target_lib_addr(pid_t pid, char * libname) {

	FILE *fp;
	char filename[30];
	char line[850];
	long addr = 0;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 850, fp) != NULL)
	{
		sscanf(line, "%lx-%*s %*s %*s %*s %*d", &addr);
		if(strstr(line, libname) != NULL)
		{
			break;
		}
	}
	fclose(fp);
	return addr;
}

long get_target_func_addr(pid_t target_pid, const char *func_name) {
    
    struct link_map *lm = NULL;
    void *injector_func_addr = NULL;
    long func_addr_offset = 0;

    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        log_message(ERROR, __func__, "Failed to open libc: %s", dlerror());
        return -1;
    }

    // Get the address of the function in our injector's libc.so.6
    injector_func_addr = dlsym(handle, func_name);
    if (injector_func_addr == NULL) {
        log_message(ERROR, __func__, "Failed to find function %s in libc: %s", func_name, dlerror());
        return -1;
    }

    // Get base address of our injector's libc.so.6 using dlinfo
    if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) != 0) {
        log_message(ERROR, __func__, "Failed to get link map for libc: %s", dlerror());
        return -1;
    }
    log_message(DEBUG, __func__, "Base Address of \"%s\" in injector: 0x%lx", lm->l_name,(long)lm->l_addr);

    // Calculate the offset of the function from the base address of libc in our injector
    func_addr_offset = (long)injector_func_addr - (long)lm->l_addr;
    log_message(DEBUG, __func__, "Offset of \"%s\" in injector: 0x%lx", func_name, func_addr_offset);

    // Now we need to find the base address of libc in the target process
    long target_libc_base_addr = get_target_lib_addr(target_pid, "libc");
    log_message(DEBUG, __func__, "Base Address of libc in target: 0x%lx", target_libc_base_addr);
    if (target_libc_base_addr == 0) {
        log_message(ERROR, __func__, "Failed to find base address of libc in target %d", target_pid);
        return -1;
    }

    // Return the address of the function in the target process
    return target_libc_base_addr + func_addr_offset;
}

void hexdump(const void *data, size_t size) {
    const unsigned char *byte_data = (const unsigned char *)data;
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", byte_data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (size % 16 != 0) {
        printf("\n");
    }
}
