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
	short settings;
} t_syscall;

# define REG_x86_64_PARAM_1 rdi
# define REG_x86_64_PARAM_2 rsi
# define REG_x86_64_PARAM_3 rdx
# define REG_x86_64_PARAM_4 r10
# define REG_x86_64_PARAM_5 r8
# define REG_x86_64_PARAM_6 r9
# define REG_x86_64_RET rax
# define REG_x86_64_SYSNUM orig_rax
# define REG_x86_64_RET_PRINT (unsigned long long int)0xfffffffffffffffe
# define REG_x86_64_RET_PRINT_BODY (unsigned long long int)0xffffffffffffffda

# define REG_i386_PARAM_1 ebx
# define REG_i386_PARAM_2 ecx
# define REG_i386_PARAM_3 edx
# define REG_i386_PARAM_4 esi
# define REG_i386_PARAM_5 edi
# define REG_i386_PARAM_6 ebp
# define REG_i386_RET eax
# define REG_i386_SYSNUM orig_eax
# define REG_i386_RET_PRINT (long int)0xfffffffe
# define REG_i386_RET_PRINT_BODY (long int)0xffffffda

# define STS_1		1 		// 00000001
# define STS_2		2 		// 00000010
# define STS_3		4 		// 00000100
# define STS_A		8 		// 00001000
# define STS_4		16 		// 00010000
# define STS_5		32 		// 00100000
# define STS_6		64 		// 01000000
# define STS_TANA   7   	// 00000111
# define STS_TA     15  	// 00001111
# define STS_TAXT	112		// 01110000

# define STS_1S		1 		// 0000000000000001
# define STS_1I		2 		// 0000000000000010
# define STS_2S		4 		// 0000000000000100
# define STS_2I		8 		// 0000000000001000
# define STS_3S		16		// 0000000000010000
# define STS_3I		32		// 0000000000100000
# define STS_AS		64		// 0000000001000000
# define STS_AI		128 	// 0000000010000000
# define STS_4S	256 	// 0000000100000000
# define STS_4I	512 	// 0000001000000000
# define STS_5S	1024 	// 0000010000000000
# define STS_5I	2048 	// 0000100000000000
# define STS_6S	4096	// 0001000000000000
# define STS_6I	8192	// 0010000000000000

extern t_syscall x86_64_syscalls[402];
extern t_syscall i386_syscalls[385];
extern t_syscall syscall_unknown;

#endif //FT_STRACE_SYSCALLS_H
