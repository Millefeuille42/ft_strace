//
// Created by millefeuille on 11/14/23.
//

#include "ft_strace.h"

void trace(void (*f)(void *), void *param) {
	const int child_pid = fork();
	switch (child_pid) {
		case -1:
			return;
		case 0:
            raise(SIGSTOP);
			f(param);
			if (errno) log_error("execve");
			break;
		default:
			ft_logstr(DEBUG, "in parent\n");
			trace_loop(child_pid);
	}
}
