#include "ptrace.h"
#include "../logging/logger.h"

static void check_target_sig(pid_t target);

bool ptrace_attach(pid_t target) {

	int waitpidstatus;

	if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
		log_message(ERROR, __func__, "Failed to PTRACE_ATTACH on target PID %d", target);
		return false;
	}

	if (waitpid(target, &waitpidstatus, WUNTRACED) != target) {
		log_message(ERROR, __func__, "Failed to stop target PID %d", target);
		return false;
	}
	return true;
}


bool ptrace_detach(pid_t target) {

	if (ptrace(PTRACE_DETACH, target, NULL, NULL) == -1) {
		log_message(ERROR, __func__, "Failed to PTRACE_DETACH on target PID %d", target);
		return false;
	}
	return true;
}


bool ptrace_getregs(pid_t target, REG* regs) {

	if (ptrace(PTRACE_GETREGS, target, NULL, regs) == -1) {
		log_message(ERROR, __func__, "Failed to PTRACE_GETREGS on target PID %d", target);
		return false;
	}
	return true;
}


bool ptrace_cont(pid_t target) {
	int status;

	if (ptrace(PTRACE_CONT, target, NULL, NULL) == -1) {
		log_message(ERROR, __func__, "Failed to PTRACE_CONT on target PID %d", target);
		return false;
	}

	if (waitpid(target, &status, 0) != target) {
		log_message(ERROR, __func__, "Failed to wait for target PID %d", target);
		return false;
	}

	if (!WIFSTOPPED(status)) {
		log_message(ERROR, __func__, "Target PID %d did not stop as expected (status: 0x%x)", target, status);
		return false;
	}

	check_target_sig(target);
	return true;
}


bool ptrace_setregs(pid_t target, REG* regs) {
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1) {
		log_message(ERROR, __func__, "Failed to PTRACE_SETREGS on target PID %d", target);
		return false;
	}
	return true;
}


bool ptrace_getsiginfo(pid_t target, siginfo_t *targetsig) {
	if (ptrace(PTRACE_GETSIGINFO, target, NULL, targetsig) == -1) {
		log_message(ERROR, __func__, "Failed to PTRACE_GETSIGINFO on target PID %d", target);
		return false;
	}
	return true;
}

bool ptrace_read(pid_t target, unsigned long addr, void *vptr, int len) {
	int bytes_read = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytes_read < len) {
		word = ptrace(PTRACE_PEEKTEXT, target, addr + bytes_read, NULL);
		if(word == -1) {
			log_message(ERROR, __func__, "Failed to PTRACE_PEEKTEXT on target PID %d", target);
			return false;
		}
		bytes_read += sizeof(word);
		ptr[i++] = word;
	}
	return true;
}

bool ptrace_write(pid_t target, unsigned long addr, void *vptr, int len)
{
	int byte_count = 0;
	long word = 0;

	while (byte_count < len) {
		memcpy(&word, vptr + byte_count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, target, addr + byte_count, word);
		if(word == -1) {
			log_message(ERROR, __func__, "Failed to PTRACE_POKETEXT on target PID %d", target);
			return false;
		}
		byte_count += sizeof(word);
	}
	return true;
}

static void check_target_sig(pid_t target) {
	// check the signal that the child stopped with.
	siginfo_t targetsig;
	
	ptrace_getsiginfo(target, &targetsig);

	// if it wasn't SIGTRAP, then something bad happened (most likely a
	// segfault).
	if(targetsig.si_signo != SIGTRAP)
	{
		log_message(ERROR, __func__, "Instead of expected SIGTRAP, target stopped with signal %d: %s", targetsig.si_signo, strsignal(targetsig.si_signo));
		log_message(ERROR, __func__, "Sending process %d a SIGSTOP signal for debugging purposes", target);
		ptrace(PTRACE_CONT, target, NULL, SIGSTOP);
		exit(1);
	}
}

void restore_state_and_detach(pid_t target, unsigned long addr, void* backup, int datasize, REG oldregs) {
	
	if (!ptrace_write(target, addr, backup, datasize)) {
		log_message(ERROR, __func__, "Failed to write backup data to target PID %d", target);
		exit(EXIT_FAILURE);
	}
	if (!ptrace_setregs(target, &oldregs)) {
		log_message(ERROR, __func__, "Failed to restore register state for target PID %d", target);
		exit(EXIT_FAILURE);
	}
	if (!ptrace_detach(target)) {
		log_message(ERROR, __func__, "Failed to detach from target PID %d", target);
		exit(EXIT_FAILURE);
	}
	return;
}