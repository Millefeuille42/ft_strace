//
// Created by millefeuille on 9/20/23.
//

#ifndef FT_STRACE_FT_STRACE_H
# define FT_STRACE_FT_STRACE_H

# include <ft_string.h>
# include <ft_error.h>
# include <sys/wait.h>
# include <sys/ptrace.h>
# include <fcntl.h>
# include <elf.h>
# include <bits/types/struct_iovec.h>

# include "syscalls.h"
# include "libtrace.h"

# define STRACE_SET_FLAG(flags, flag) (flags |= flag)
# define STRACE_CLEAR_FLAG(flags, flag) (flags &= ~(flag))
# define STRACE_HAS_FLAG(flags, flag) (flags & flag)

# ifndef STRACE_MAX_STRING_SIZE
#  define STRACE_MAX_STRING_SIZE 32
# endif

extern char signals[35][11];

typedef struct s_i386_regset {
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
} i386_regset;

typedef struct s_x86_64_regset {
	__extension__ unsigned long long int r15;
	__extension__ unsigned long long int r14;
	__extension__ unsigned long long int r13;
	__extension__ unsigned long long int r12;
	__extension__ unsigned long long int rbp;
	__extension__ unsigned long long int rbx;
	__extension__ unsigned long long int r11;
	__extension__ unsigned long long int r10;
	__extension__ unsigned long long int r9;
	__extension__ unsigned long long int r8;
	__extension__ unsigned long long int rax;
	__extension__ unsigned long long int rcx;
	__extension__ unsigned long long int rdx;
	__extension__ unsigned long long int rsi;
	__extension__ unsigned long long int rdi;
	__extension__ unsigned long long int orig_rax;
	__extension__ unsigned long long int rip;
	__extension__ unsigned long long int cs;
	__extension__ unsigned long long int eflags;
	__extension__ unsigned long long int rsp;
	__extension__ unsigned long long int ss;
	__extension__ unsigned long long int fs_base;
	__extension__ unsigned long long int gs_base;
	__extension__ unsigned long long int ds;
	__extension__ unsigned long long int es;
	__extension__ unsigned long long int fs;
	__extension__ unsigned long long int gs;
} x86_64_regset;

struct command_struct {
	char *command;
	char **argv;
	char **env;
};

void i386_print_syscall_info(const t_syscall* syscall, const i386_regset* regs, int pid);

void x86_64_print_syscall_info(const t_syscall* syscall, const x86_64_regset* regs, int pid);

void print_registry(const t_syscall* syscall, int registry_num, size_t registry, int pid);

void print_signal_info(const siginfo_t* siginfo);

void print_signal_stop(const siginfo_t* siginfo);

void trace_loop(int pid);

int find_least_significant_bit_position(int value);

void ft_putstr_escape(const char* str, size_t read_size);


#endif //FT_STRACE_FT_STRACE_H
