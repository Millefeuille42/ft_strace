#include "ft_strace.h"
#include <sys/stat.h>

static char* find_command_in_path(const char* command, char** env) {
	char env_name_buf[6] = {0};
	struct stat stat_buf;
	char* end_of_path = NULL;
	const char* last_pos = NULL;
	char* ret = NULL;

	for (int i = 0; env[i]; i++) {
		const size_t len = ft_strlen(env[i]);
		if (len <= 5) continue;
		ft_string_copy(env[i], env_name_buf, 5);
		if (ft_strcmp("PATH=", env_name_buf)) continue;

		last_pos = env[i] + 5;
		for (size_t path_i = 1; path_i < len; path_i++) {
			errno = 0;
			end_of_path = get_after_n_sep(env[i], ':', path_i);
			if (end_of_path != env[i]) end_of_path[-1] = '\0';
			const int dir_fd = open(last_pos, __O_PATH | O_DIRECTORY);
			end_of_path[-1] = ':';
			if (errno) {
				last_pos = end_of_path;
				continue;
			}
			fstatat(dir_fd, command, &stat_buf, 0);
			if (errno) {
				close(dir_fd);
				last_pos = end_of_path;
				continue;
			}
			close(dir_fd);
			const size_t size = (size_t)(end_of_path - last_pos);
			ret = malloc(sizeof(char) * size + ft_strlen(command) + 1);
			if (!ret) return NULL;
			ft_string_copy(last_pos, ret, size);
			ret[size - 1] = '/';
			ft_string_copy(command, ret + size, ft_strlen(command));
			ret[sizeof(char) * size + ft_strlen(command)] = 0;
			errno = 0;
			return ret;
		}
	}

	errno = 0;
	return ret;
}

static void start_command(char* command, char** argv, char** env) {
	ft_logstr(DEBUG, "Starting process with following arguments \n");
	for (int i = 0; argv[i]; i++) {
		ft_logstr(DEBUG, argv[i]);
		ft_logstr_no_header(DEBUG, "\n");
	}

	struct stat stat_buf;
	fstatat(AT_FDCWD, argv[0], &stat_buf, 0);
	if (errno) {
		command = find_command_in_path(command, env);
		if (!command) panic("not found");
	}
	else {
		command = ft_string(command);
		if (!command) panic("malloc error");
	}

	const int child_pid = fork();
	switch (child_pid) {
		case -1:
			return;
		case 0:
			execve(command, argv, env);
			if (errno) log_error("execve");
			ft_logstr(DEBUG, "child is done\n");
			break;
		default:
			ft_logstr(DEBUG, "in parent\n");
			trace_loop(child_pid);
			ft_logstr(DEBUG, "Parent exited\n");
	}
	safe_free((void **)&command);
}

int main(const int argc, char* argv[], char* env[]) {
	if (argc <= 1) {
		ft_fputstr("ft_strace: must have PROG [ARGS] or -p PID\nTry 'ft_strace -h' for more information.\n", 2);
		return 1;
	}

	start_command(argv[1], argv + 1, env);
	return errno;
}
