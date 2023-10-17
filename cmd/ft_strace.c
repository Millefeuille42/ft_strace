#include "ft_strace.h"

void start_command(char *command, char **argv) {
	ft_logstr(DEBUG, "Starting process with following arguments \n");
	for (int i = 0; argv[i]; i++) {
		ft_logstr(DEBUG, argv[i]);
		ft_logstr_no_header(DEBUG, "\n");
	}

	int child_pid = fork();
	switch (child_pid) {
		case -1:
			return;
		case 0:
			// TODO this breaks nested calls to ./ft_strace (to investigate)
			//(void)child_pid;
			//int dev_null_fd = open("/dev/null", O_WRONLY);
			//if (errno) panic("child open");
			//dup2(dev_null_fd, STDOUT_FILENO);
			//if (errno) panic("child dup2 STDOUT");
			//dup2(dev_null_fd, STDERR_FILENO);
			//if (errno) panic("child dup2 STDERR");
			//close(dev_null_fd);
			//if (errno) panic("child close");

			execvp(command, argv);
			if (errno)panic("execvp");
			ft_logstr(DEBUG, "child is done\n");
			break;
		default:
			ft_logstr(DEBUG, "in parent\n");
			trace_loop(child_pid);
			ft_logstr(DEBUG, "Parent exited\n");
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
