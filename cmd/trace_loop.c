//
// Created by millefeuille on 10/17/23.
//

#include "ft_strace.h"

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

static void i386_handle_syscall(t_syscall* syscall, const i386_regset* regs, char* has_body, char* has_ret, const int pid) {
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

static void x86_64_handle_syscall(t_syscall* syscall, const x86_64_regset* regs, char* has_body, char* has_ret,
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

static sigset_t prepare_child(const int pid) {
	ft_logstr(DEBUG, "seized child\n");
    sigset_t blocked;
    sigemptyset(&blocked);
    sigprocmask(SIG_SETMASK, &blocked, NULL);

    int status = 0;
    waitpid(pid, &status, 0);
    ft_logstr(DEBUG, "Setting up sigprocmask\n");
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGQUIT);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGPIPE);
    sigprocmask(SIG_BLOCK, &blocked, NULL);
	ft_logstr(DEBUG, "child started\n");
    return blocked;
}

void trace_loop(int const pid) {
	char child_ready = 0;
	char has_ret = 0;
	char has_body = 0;
	int status = 0;
    int sig = 0;
	
	ft_logstr(DEBUG, "Setting up ptrace\n");
	ptrace(PTRACE_SEIZE, pid, NULL, NULL);
	ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);

    sigset_t core = create_core_set();
    sigset_t blocked = prepare_child(pid);
	ft_logstr(DEBUG, "tracking ready, starting loop\n");
	ft_lognbr_in_between(DEBUG, "pid of child: ", pid, "\n", 0);


	while (1) {
        if (sig && sigismember(&blocked, sig)) ptrace(PTRACE_SYSCALL, pid, NULL, sig);
        else ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

		waitpid(pid, &status, 0);
		if (errno) panic("waitpid");
		if (check_child_exit(status, has_ret)) break;
		if (check_child_signal_exit(status, has_ret, pid)) break;

        // Signal handling
		siginfo_t siginfo;
        if (!ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
            sig = siginfo.si_signo;
            if (WSTOPSIG(status) != SIGTRAP) {
                print_signal_info(&siginfo);
            }

            if (WSTOPSIG(status) != SIGCONT) {
                if (sigismember(&core, siginfo.si_signo)) {
                    if (!has_ret) ft_putstr(" = ?\n");
                    print_signal_stop(&siginfo);
                    break;
                }
            }
        }

        // generic syscall handling
        struct iovec io = {
                .iov_base = &x86_regs_union,
                .iov_len = sizeof(x86_regs_union)
        };

        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io) < 0) {
            if (!has_ret) ft_putstr(" = ?\n");
            ft_lognbr_in_between(INFO, "child exited with status ", WEXITSTATUS(status), "\n", 0);
            break;
        }

		t_syscall* syscall = NULL;
		if (io.iov_len == sizeof(i386_regset)) {
			syscall = i386_get_syscall_info(&i386_regs);
			i386_handle_syscall(syscall, &i386_regs, &has_body, &has_ret, pid);
		}
		else {
			syscall = x86_64_get_syscall_info(&x86_64_regs);
			x86_64_handle_syscall(syscall, &x86_64_regs, &has_body, &has_ret, pid);
		}
	}
}
