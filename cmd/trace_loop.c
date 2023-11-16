//
// Created by millefeuille on 10/17/23.
//

#include "ft_strace.h"

static void prepare_child(const int pid) {
	ft_logstr(DEBUG, "seized child\n");
	kill(pid, SIGCONT);
	ptrace(PTRACE_LISTEN, pid, NULL, NULL);
	ft_logstr(DEBUG, "child started\n");
}

static int check_child_exit(const int status, const char has_ret) {
	if (WIFEXITED(status)) {
		if (!has_ret) ft_putstr(" = ?\n");
		ft_lognbr_in_between(INFO, "child exited with status ", WEXITSTATUS(status), "\n", 0);
		return 1;
	}
	return 0;
}

static int check_child_signal_exit(const int status, const char has_ret, const int pid) {
	if (WIFSIGNALED(status)) {
		if (!has_ret) ft_putstr(" = ?\n");
		siginfo_t siginfo;
		ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
		print_signal_info(&siginfo);
		ft_logstr(INFO, "child exited due to signal\n");
		return 1;
	}
	return 0;
}

static t_syscall* i386_get_syscall_info(const i386_regset* regs) {
	t_syscall* syscall = &syscall_unknown;
	if ((size_t)regs->REG_i386_SYSNUM < sizeof(i386_syscalls) / sizeof(t_syscall))
		syscall = &i386_syscalls[regs->REG_i386_SYSNUM];
	syscall->read_size = ft_strcmp(syscall->name, "write") == 0 ? (size_t)regs->REG_i386_PARAM_3 : 0;

	return syscall;
}

static t_syscall* x86_64_get_syscall_info(const x86_64_regset* regs) {
	t_syscall* syscall = &syscall_unknown;
	if ((size_t)regs->REG_x86_64_SYSNUM < sizeof(x86_64_syscalls) / sizeof(t_syscall))
		syscall = &x86_64_syscalls[regs->REG_x86_64_SYSNUM];
	syscall->read_size = ft_strcmp(syscall->name, "write") == 0 ? (size_t)regs->REG_x86_64_PARAM_3 : 0;

	return syscall;
}

static void i386_trace_loop(t_syscall* syscall, const i386_regset* regs, char* has_body, char* has_ret, const int pid) {
	if (regs->REG_i386_RET != REG_i386_RET_PRINT) {
		if (regs->REG_i386_RET != REG_i386_RET_PRINT_BODY) {
			if (*has_body) {
				ft_putstr(" = ");
				STRACE_SET_FLAG(syscall->toggle, STS_A);
				print_registry(syscall, STS_A, regs->REG_i386_RET, pid);
				ft_putstr("\n");
			}
			*has_ret = 1;
			*has_body = 0;
		}
		else if (*has_ret) {
			i386_print_syscall_info(syscall, regs, pid);
			*has_ret = 0;
			*has_body = 1;
		}
	}
}

static void x86_64_trace_loop(t_syscall* syscall, const x86_64_regset* regs, char* has_body, char* has_ret,
                              const int pid) {
	if (regs->REG_x86_64_RET != REG_x86_64_RET_PRINT) {
		if (regs->REG_x86_64_RET != REG_x86_64_RET_PRINT_BODY) {
			if (*has_body) {
				ft_putstr(" = ");
				STRACE_SET_FLAG(syscall->toggle, STS_A);
				print_registry(syscall, STS_A, regs->REG_x86_64_RET, pid);
				ft_putstr("\n");
			}
			*has_ret = 1;
			*has_body = 0;
		}
		else if (*has_ret) {
			x86_64_print_syscall_info(syscall, regs, pid);
			*has_ret = 0;
			*has_body = 1;
		}
	}
}

void trace_loop(int const pid) {
	char child_ready = 0;
	char has_ret = 0;
	char has_body = 0;
	sigset_t empty;
	sigemptyset(&empty);
	sigset_t blocked = empty;
	sigset_t core = empty;
	sigaddset(&blocked, SIGHUP);
	sigaddset(&blocked, SIGINT);
	sigaddset(&blocked, SIGQUIT);
	sigaddset(&blocked, SIGTERM);
	sigaddset(&blocked, SIGPIPE);
	sigaddset(&core, SIGILL);
	sigaddset(&core, SIGABRT);
	sigaddset(&core, SIGFPE);
	sigaddset(&core, SIGBUS);
	sigaddset(&core, SIGSEGV);
	sigaddset(&core, SIGSYS);
	ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACEEXEC);
	ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	sigprocmask(SIG_SETMASK, &empty, NULL);
	sigprocmask(SIG_BLOCK, &blocked, NULL);

	while (1) {
		int status = 0;
		waitpid(pid, &status, 0);
		if (errno) panic("waitpid");
		if (check_child_exit(status, has_ret)) break;
		if (check_child_signal_exit(status, has_ret, pid)) break;

		siginfo_t siginfo;
		ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);

		if (WSTOPSIG(status) != SIGTRAP) {
			print_signal_info(&siginfo);
		}

		if (WSTOPSIG(status) != SIGCONT) {
			if (siginfo.si_signo == SIGTRAP && !child_ready) {
				prepare_child(pid);
				child_ready = 1;
				continue;
			}
			if (sigismember(&core, siginfo.si_signo)) {
				if (!has_ret) ft_putstr(" = ?\n");
				print_signal_stop(&siginfo);
				break;
			}
			if (siginfo.si_signo == SIGINT) {
				if (!has_ret) ft_putstr(" = ?\n");
				ft_logstr(INFO, "child detached\n");
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				break;
			}
		}

		static union {
			x86_64_regset x86_64_r;
			i386_regset i386_r;
		} x86_regs_union;
# define x86_64_regs x86_regs_union.x86_64_r
# define i386_regs   x86_regs_union.i386_r

		struct iovec io = {
			.iov_base = &x86_regs_union,
			.iov_len = sizeof(x86_regs_union)
		};
		ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);

		t_syscall* syscall = NULL;
		if (io.iov_len == sizeof(i386_regset)) {
			syscall = i386_get_syscall_info(&i386_regs);
			i386_trace_loop(syscall, &i386_regs, &has_body, &has_ret, pid);
		}
		else {
			syscall = x86_64_get_syscall_info(&x86_64_regs);
			x86_64_trace_loop(syscall, &x86_64_regs, &has_body, &has_ret, pid);
		}

		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}
}
