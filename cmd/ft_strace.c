#include "ft_strace.h"

int find_least_significant_bit_position(int value) {
	if (value == 0) return 0;

	int position = 0;
	for (; !(value & 1); position++) value >>= 1;
	return position;
}

void ft_putstr_escape(char *str, size_t read_size) {
	if (!str)
		return;
	size_t len = 0;
	for (; str[len] && len != read_size; len++) {
		if (str[len] == '\n') {
			write(1, "\\n", 2);
			continue;
		}
		write(1, &str[len], 1);
	}
}

int print_string_from_child(int pid, long address, size_t read_size) {
	// TODO protect all of this
	int fd;
	{
		char filename_buffer[sizeof("/proc//mem") + 32];
		ft_bzero(filename_buffer, sizeof(filename_buffer));
		sprintf(filename_buffer, "/proc/%d/mem", pid);
		fd = open(filename_buffer, O_RDONLY);
		if (errno) {
			perror("open");
			return 1;
		}
	}

	lseek(fd, address, SEEK_SET);
	if (errno) {
		close(fd);
		log_error("lseek");
		return 1;
	}

	int exit = 0;
	char buffer[1024];
	ft_bzero(buffer, sizeof(buffer));

	for (;!exit;) {
		read(fd, buffer, sizeof(buffer) - 1);
		if (errno) {
			close(fd);
			log_error("read_loop");
			return 1;
		}

		ft_putstr_escape(buffer, read_size);
		for (size_t pos = 0; pos < sizeof(buffer) - 1; pos++) if (buffer[pos] == '\0') exit = 1;

		ft_bzero(buffer, sizeof(buffer));
	}

	return 0;
}

void print_registry(t_syscall *const syscall, int registry_num, void *registry, int pid) {
	if (!STRACE_HAS_FLAG(syscall->toggle, registry_num)) return;

	int least_position = find_least_significant_bit_position(registry_num);
	if (least_position && registry_num != STS_A)
		ft_putstr(", ");
	if (registry_num == STS_A)
		ft_putstr(" = ");

	int offset = 1 << (2 * least_position);
	// Check for S bit (is string)
	if (STRACE_HAS_FLAG(syscall->settings, offset)) {
		ft_putstr("\"");
		print_string_from_child(pid, (long)registry, syscall->read_size);
		ft_putstr("\"");
		return;
	}

	offset <<= 1;
	// Check for I bit (is integer)
	if (STRACE_HAS_FLAG(syscall->settings, offset)) {
		ft_putnbr((long)registry);
		return;
	}

	// Fallback, print pointer
	if (!registry) ft_putstr("NULL");
	else {
		printf("%p", registry);
		fflush(stdout);
	}
}

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

			execvp(command, argv);
			break;
		default:
			ptrace(PTRACE_SEIZE, child_pid, NULL, PTRACE_O_TRACEEXEC);

			ft_logstr(DEBUG, "in parent\n");
			struct user_regs_struct regs;
			struct iovec io;
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
				io.iov_base = &regs;
				io.iov_len = sizeof(regs);
				ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &io);
				// TODO Check behavior on 32 bits
				if (regs.rax == 0xffffffffffffffda) {
					ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
					continue;
				}
				t_syscall * const syscall = &syscalls[regs.orig_rax];
				syscall->read_size = ft_strcmp(syscall->name, "write") == 0 ? regs.rdx : -1;
				ft_putstr(syscall->name);
				ft_putstr("(");
				if (STRACE_HAS_FLAG(syscall->toggle, STS_B)) print_registry(syscall, STS_B, (void *)regs.rdi, child_pid);
				if (STRACE_HAS_FLAG(syscall->toggle, STS_C)) print_registry(syscall, STS_C, (void *)regs.rsi, child_pid);
				if (STRACE_HAS_FLAG(syscall->toggle, STS_D)) print_registry(syscall, STS_D, (void *)regs.rdx, child_pid);
				ft_putstr(")");
				if (STRACE_HAS_FLAG(syscall->toggle, STS_A)) print_registry(syscall, STS_A, (void *)regs.rax, child_pid);
				ft_putstr("\n");
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
