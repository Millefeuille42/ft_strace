//
// Created by millefeuille on 9/20/23.
//

#ifndef FT_STRACE_FT_STRACE_H
# define FT_STRACE_FT_STRACE_H

# include <ft_print.h>
# include <ft_list.h>
# include <ft_string.h>
# include <ft_error.h>
# include <sys/wait.h>
# include <sys/ptrace.h>
# include <fcntl.h>
# include <sys/user.h>
# include <elf.h>
# include <bits/types/struct_iovec.h>

# include "syscalls.h"
# include "signals.h"

# define STRACE_FLAG_dirs           32              // 00100000

# define STRACE_SET_FLAG(flags, flag) (flags |= flag)
# define STRACE_CLEAR_FLAG(flags, flag) (flags &= ~(flag))
# define STRACE_HAS_FLAG(flags, flag) (flags & flag)

// TODO implement string size
# define STRACE_MAX_STRING_SIZE 16

typedef struct s_strace_args {
	ft_list *files;
	char flags;
	int err;
} strace_args;


void print_syscall_info(t_syscall *syscall, struct user_regs_struct *regs, int pid);
void print_registry(t_syscall *syscall, int registry_num, void *registry, int pid);
void print_signal_info(siginfo_t *siginfo);
void print_signal_stop(siginfo_t *siginfo);

void trace_loop(int pid);

strace_args parse_args(int argc, char **argv);

int find_least_significant_bit_position(int value);
void ft_putstr_escape(char *str, size_t read_size);


#endif //FT_STRACE_FT_STRACE_H
