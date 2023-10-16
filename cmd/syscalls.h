//
// Created by millefeuille on 9/20/23.
//

#ifndef FT_STRACE_SYSCALLS_H
# define FT_STRACE_SYSCALLS_H

#include <stddef.h>

typedef struct s_syscall {
	size_t read_size;
	char name[32];
	char toggle;
	char settings;
} t_syscall;

// TODO add support of 4 5 6 parameters (r10, r8, r9)

# define STS_B		1 	// 00000001
# define STS_C		2 	// 00000010
# define STS_D		4 	// 00000100
# define STS_A		8 	// 00001000
# define STS_TANA   7   // 00000111
# define STS_TA     15  // 00001111

# define STS_BS	1 	// 00000001
# define STS_BI	2 	// 00000010
# define STS_CS	4 	// 00000100
# define STS_CI	8 	// 00001000
# define STS_DS	16	// 00010000
# define STS_DI	32	// 00100000
# define STS_AS	64	// 01000000
# define STS_AI	128 // 10000000

# define STRACE_SET_FLAG(flags, flag) (flags |= flag)
# define STRACE_CLEAR_FLAG(flags, flag) (flags &= ~(flag))
# define STRACE_HAS_FLAG(flags, flag) (flags & flag)

extern t_syscall syscalls[400];

#endif //FT_STRACE_SYSCALLS_H
