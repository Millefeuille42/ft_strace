//
// Created by millefeuille on 9/20/23.
//

#ifndef FT_STRACE_FT_STRACE_H
# define FT_STRACE_FT_STRACE_H

# include <ft_print.h>
# include <ft_list.h>
# include <ft_string.h>
# include <ft_error.h>

# include "syscalls.h"

# define STRACE_FLAG_dirs           32              // 00100000

# define STRACE_SET_FLAG(flags, flag) (flags |= flag)
# define STRACE_CLEAR_FLAG(flags, flag) (flags &= ~(flag))
# define STRACE_HAS_FLAG(flags, flag) (flags & flag)

typedef struct s_strace_args {
	ft_list *files;
	char flags;
	int err;
} strace_args;

strace_args parse_args(int argc, char **argv);

#endif //FT_STRACE_FT_STRACE_H
