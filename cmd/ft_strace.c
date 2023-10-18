#include "ft_strace.h"
#include <sys/stat.h>

void start_command(const char *command, char **argv, char **env) {
	ft_logstr(DEBUG, "Starting process with following arguments \n");
	for (int i = 0; argv[i]; i++) {
		ft_logstr(DEBUG, argv[i]);
		ft_logstr_no_header(DEBUG, "\n");
	}

	struct stat stat_buf;
	fstatat(AT_FDCWD, argv[0], &stat_buf, 0);
	if (errno) panic("fstatat");

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

			execve(command, argv, env);
			if (errno)panic("execvp");
			ft_logstr(DEBUG, "child is done\n");
			break;
		default:
			ft_logstr(DEBUG, "in parent\n");
			trace_loop(child_pid);
			ft_logstr(DEBUG, "Parent exited\n");
	}
}

// TODO investigate difference with discord
int main(int argc, char *argv[], char *env[]) {
	if (argc <= 1) {
		ft_fputstr("ft_strace: must have PROG [ARGS] or -p PID\nTry 'ft_strace -h' for more information.\n", 2);
		return 1;
	}

	start_command(argv[1], argv + 1, env);
	return errno;
}
