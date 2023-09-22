#include "ft_strace.h"
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sys/user.h>

void start_command(char *command, char **argv) {
	int child_pid = fork();
	switch (child_pid) {
		case -1:
			return;
		case 0:
			ft_logstr(DEBUG, "in child\n");
			int dev_null_fd = open("/dev/null", O_WRONLY);
			if (errno) panic("child open");
			dup2(dev_null_fd, STDOUT_FILENO);
			if (errno) panic("child dup2 STDOUT");
			dup2(dev_null_fd, STDERR_FILENO);
			if (errno) panic("child dup2 STDERR");
			close(dev_null_fd);
			if (errno) panic("child close");
			ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			execvp(command, argv);
			break;
		default:
			ft_logstr(DEBUG, "in parent\n");
			struct user_regs_struct regs;
			while (1) {
				int status = 0;
				waitpid(child_pid, &status, 0);
				if (errno) panic("waitpid");
				if (WIFEXITED(status)) {
					ft_logstr(DEBUG, "child exited\n");
					break;
				}
				if (WIFSIGNALED(status)) {
					ft_logstr(DEBUG, "child exited due to signal\n");
					break;
				}
				if (WSTOPSIG(status) != SIGTRAP) {
					ft_logstr(DEBUG, "child stopped due to signal\n");
					continue;
				}
				ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
				// TODO Check behavior on 32 bits
				if (regs.rax == 0xffffffffffffffda) {
					ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
					continue;
				}
				// TODO This is ugly, fix the sizeof
				unsigned long long offset = regs.orig_rax * sizeof(char[29]);
				char *syscall = (char *)syscalls + offset;
				printf("%s(%p, %p, %p) = %lld\n", syscall, (void *)regs.rbx, (void *)regs.rcx, (void *)regs.rdx, (long long)regs.rax);
				ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
			}
	}
}

int main(int argc, char *argv[]) {
	strace_args args = parse_args(argc, argv);
	if (args.err) {
		if (args.err == -2) return 1;
		panic("allocation");
	}

	if (!args.files) {
		ft_fputstr("ft_strace: must have PROG [ARGS] or -p PID\nTry 'ft_strace -h' for more information.\n", 2);
		return 1;
	}

	start_command(argv[1], argv + 1);
	ft_list *current = args.files;
	errno = 0;
	if (errno) log_error(current->data);

	delete_list_forward(&args.files, safe_free);
	return errno;
}
