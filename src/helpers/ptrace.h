#ifndef HELPERS_PTRACE_H
#define HELPERS_PTRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

#ifdef ARM
	#define REG_TYPE user_regs
#else
	#define REG_TYPE user_regs_struct
#endif

bool ptrace_attach(pid_t target);
bool ptrace_detach(pid_t target);
bool ptrace_getregs(pid_t target, struct REG_TYPE* regs);
bool ptrace_cont(pid_t target);
bool ptrace_setregs(pid_t target, struct REG_TYPE* regs);
bool ptrace_getsiginfo(pid_t target, siginfo_t *targetsig);
bool ptrace_read(int pid, unsigned long addr, void *vptr, int len);
bool ptrace_write(int pid, unsigned long addr, void *vptr, int len);
void restore_state_and_detach(pid_t target, unsigned long addr, void* backup, int datasize, struct REG_TYPE oldregs);

#endif