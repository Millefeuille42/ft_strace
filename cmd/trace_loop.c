//
// Created by millefeuille on 10/17/23.
//

#include "ft_strace.h"

inline static void prepare_child(int pid) {
	ft_logstr(DEBUG, "seized child\n");
	kill(pid, SIGCONT);
	ptrace(PTRACE_LISTEN, pid, NULL, NULL);
	ft_logstr(DEBUG, "child started\n");
}

inline static int check_child_exit(int status, char has_ret) {
	if (WIFEXITED(status)) {
		if (!has_ret) ft_putstr(" = ?\n");
		ft_lognbr_in_between(INFO, "child exited with status ", WEXITSTATUS(status), "\n", 0);
		return 1;
	}
	return 0;
}

inline static int check_child_signal_exit(int status, char has_ret, int pid) {
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

inline static t_syscall *get_syscall_info(struct user_regs_struct *regs) {
	t_syscall *syscall = &syscall_unknown;
	if (regs->orig_rax < sizeof(syscalls) / sizeof(t_syscall)) syscall = &syscalls[regs->orig_rax];
	syscall->read_size = ft_strcmp(syscall->name, "write") == 0 ? regs->rdx : -1;

	return syscall;
}

void trace_loop(int pid) {
	struct iovec io;
	struct user_regs_struct regs;
	char child_ready = 0;
	char has_ret = 0;
	char has_body = 0;

	ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACEEXEC);
	ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);

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
			if (siginfo.si_signo != SIGTRAP) {
				if (!has_ret) ft_putstr(" = ?\n");
				print_signal_stop(&siginfo);
				break;
			}
		}

		io.iov_base = &regs;
		io.iov_len = sizeof(regs);
		ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
		t_syscall *syscall = get_syscall_info(&regs);

		// TODO Check behavior on 32 bits
		if (regs.rax != 0xfffffffffffffffe) {
			if (regs.rax != 0xffffffffffffffda) {
				if (has_body) {
					ft_putstr(" = ");
					if (STRACE_HAS_FLAG(syscall->toggle, STS_A)) print_registry(syscall, STS_A, (void *)regs.rax, pid);
					ft_putstr("\n");
				}
				has_ret = 1;
				has_body = 0;
			} else if (has_ret) {
				print_syscall_info(syscall, &regs, pid);
				has_ret = 0;
				has_body = 1;
			}
		}
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}
}
