//
// Created by millefeuille on 9/20/23.
//

#include "syscalls.h"

t_syscall syscall_unknown = (t_syscall){.name = "UNKNOWN", .toggle = STS_TA};

t_syscall x86_64_syscalls[402] = {
	{
		.name = "read",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "write",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "open",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I | STS_3I
	},
	{
		.name = "close",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "newstat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "newfstat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "newlstat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "poll",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "lseek",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "mmap",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "mprotect",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "munmap",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "brk",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "rt_sigaction",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_5I
	},
	{
		.name = "rt_sigprocmask",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "rt_sigreturn",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "ioctl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "pread64",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "pwrite64",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I
	},
	{
		.name = "readv",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "writev",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "access",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "pipe",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "select",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_5I
	},
	{
		.name = "sched_yield",
		.toggle = STS_1,
	},
	{
		.name = "mremap",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "msync",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "mincore",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4S
	},
	{
		.name = "madvise",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "shmget",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "shmat",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "shmctl",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "dup",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "dup2",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "pause",
		.toggle = STS_1,
	},
	{
		.name = "nanosleep",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "getitimer",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "alarm",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "setitimer",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "getpid",
		.toggle = STS_1,
	},
	{
		.name = "sendfile64",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "socket",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "connect",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "accept",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "sendto",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "recvfrom",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "sendmsg",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I
	},
	{
		.name = "recvmsg",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I
	},
	{
		.name = "shutdown",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "bind",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "listen",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "getsockname",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "getpeername",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "socketpair",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "setsockopt",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3I | STS_4S | STS_5I
	},
	{
		.name = "getsockopt",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3I | STS_4S | STS_5I
	},
	{
		.name = "clone",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "fork",
		.toggle = STS_1,
	},
	{
		.name = "vfork",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "execve",
		.toggle = STS_TA,
		.settings = STS_1S
	},
	{
		.name = "exit",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "wait4",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "kill",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "newuname",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "semget",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "semop",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "semctl",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "shmdt",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "msgget",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "msgsnd",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "msgrcv",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "msgctl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "fcntl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "flock",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "fsync",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "fdatasync",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "truncate",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "ftruncate",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "getdents",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "getcwd",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "chdir",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "fchdir",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "rename",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2S
	},
	{
		.name = "mkdir",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "rmdir",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "creat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "link",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2S
	},
	{
		.name = "unlink",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "symlink",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2S
	},
	{
		.name = "readlink",
		.toggle = STS_TA,
		.settings = STS_1S | STS_3I
	},
	{
		.name = "chmod",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "fchmod",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "chown",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "fchown",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "lchown",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "umask",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "gettimeofday",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "getrlimit",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "getrusage",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "sysinfo",
		.toggle = STS_1,
	},
	{
		.name = "times",
		.toggle = STS_1,
	},
	{
		.name = "ptrace",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getuid",
		.toggle = STS_1,
	},
	{
		.name = "syslog",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "getgid",
		.toggle = STS_1,
	},
	{
		.name = "setuid",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "setgid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "geteuid",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "getegid",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "setpgid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "getppid",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "getpgrp",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "setsid",
		.toggle = STS_1,
	},
	{
		.name = "setreuid",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "setregid",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "getgroups",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "setgroups",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "setresuid",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "getresuid",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "setresgid",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "getresgid",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "getpgid",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "setfsuid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setfsgid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "getsid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "capget",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "capset",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "rt_sigpending",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "rt_sigtimedwait",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "rt_sigqueueinfo",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "rt_sigsuspend",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "sigaltstack",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "utime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "mknod",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "personality",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "ustat",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "statfs",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "fstatfs",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "sysfs",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getpriority",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "setpriority",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "sched_setparam",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "sched_getparam",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "sched_setscheduler",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "sched_getscheduler",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sched_get_priority_max",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sched_get_priority_min",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sched_rr_get_interval",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "mlock",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "munlock",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "mlockall",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "munlockall",
		.toggle = STS_1,
	},
	{
		.name = "vhangup",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",

	},
	{
		.name = "not implemented",

	},
	{
		.name = "pivot_root",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S
	},
	{
		.name = "ni_syscall",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "prctl",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "adjtimex",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setrlimit",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "chroot",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "sync",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "acct",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "settimeofday",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "mount",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2S | STS_3S | STS_4S | STS_5I
	},
	{
		.name = "umount",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "swapon",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "swapoff",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "reboot",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "sethostname",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "setdomainname",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "ioperm",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "init_module",
		.toggle = STS_TA | STS_4,
		.settings = STS_3I | STS_4S
	},
	{
		.name = "delete_module",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "quotactl",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "gettid",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "readahead",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "setxattr",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2S | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "lsetxattr",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2S | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "fsetxattr",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "getxattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "lgetxattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "fgetxattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "listxattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "llistxattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "flistxattr",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "removexattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S
	},
	{
		.name = "lremovexattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S
	},
	{
		.name = "fremovexattr",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "tkill",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "time",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "futex",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_3I | STS_5I
	},
	{
		.name = "sched_setaffinity",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "sched_getaffinity",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "io_setup",
		.toggle = STS_TA,
		.settings = STS_3I
	},
	{
		.name = "io_destroy",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "io_getevents",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_6I
	},
	{
		.name = "io_submit",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "io_cancel",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "lookup_dcookie",
		.toggle = STS_TA | STS_4,
		.settings = STS_3S | STS_4I
	},
	{
		.name = "epoll_create",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "remap_file_pages",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "getdents64",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "set_tid_address",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "restart_syscall",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "semtimedop",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_5I
	},
	{
		.name = "fadvise64",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "timer_create",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "timer_settime",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "timer_gettime",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "timer_getoverrun",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "timer_delete",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "clock_settime",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "clock_gettime",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "clock_getres",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "clock_nanosleep",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "exit_group",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "epoll_wait",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_5I
	},
	{
		.name = "epoll_ctl",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "tgkill",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "utimes",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "mbind",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "set_mempolicy",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "get_mempolicy",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "mq_open",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "mq_unlink",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "mq_timedsend",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "mq_timedreceive",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "mq_notify",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "mq_getsetattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I
	},
	{
		.name = "kexec_load",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "waitid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "add_key",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "request_key",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3S | STS_4S | STS_5I
	},
	{
		.name = "keyctl",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "ioprio_set",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "ioprio_get",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "inotify_init",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "inotify_add_watch",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "inotify_rm_watch",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "migrate_pages",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "openat",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I
	},
	{
		.name = "mkdirat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "mknodat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "fchownat",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "futimesat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "newfstatat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_4I
	},
	{
		.name = "unlinkat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "renameat",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2S | STS_3I | STS_4S
	},
	{
		.name = "linkat",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2S | STS_3I | STS_4S | STS_5I
	},
	{
		.name = "symlinkat",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4S
	},
	{
		.name = "readlinkat",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_4S | STS_5I
	},
	{
		.name = "fchmodat",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "faccessat",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "pselect6",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_6I
	},
	{
		.name = "ppoll",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "unshare",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "set_robust_list",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "get_robust_list",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "splice",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "tee",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "sync_file_range",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "vmsplice",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "move_pages",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "utimensat",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I
	},
	{
		.name = "epoll_pwait",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "signalfd",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "timerfd_create",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "eventfd",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "fallocate",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "timerfd_settime",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "timerfd_gettime",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "accept4",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "signalfd4",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "eventfd2",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "epoll_create1",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "dup3",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "pipe2",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "inotify_init1",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "preadv",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "pwritev",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "rt_tgsigqueueinfo",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "perf_event_open",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "recvmmsg",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_6I
	},
	{
		.name = "fanotify_init",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "fanotify_mark",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_5I | STS_6S
	},
	{
		.name = "prlimit64",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "name_to_handle_at",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "open_by_handle_at",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "clock_adjtime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "syncfs",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sendmmsg",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "setns",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "getcpu",
		.toggle = STS_TA,
	},
	{
		.name = "process_vm_readv",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_5I | STS_6I
	},
	{
		.name = "process_vm_writev",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_5I | STS_6I
	},
	{
		.name = "kcmp",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "finit_module",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "sched_setattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "sched_getattr",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_5I
	},
	{
		.name = "renameat2",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_4I | STS_5S | STS_6I
	},
	{
		.name = "seccomp",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "getrandom",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "memfd_create",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "kexec_file_load",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3I | STS_4S | STS_5I
	},
	{
		.name = "bpf",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "execveat",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_5I
	},
	{
		.name = "userfaultfd",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "membarrier",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "mlock2",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "copy_file_range",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "preadv2",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "pwritev2",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "pkey_mprotect",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "pkey_alloc",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "pkey_free",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "statx",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "io_pgetevents",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_6I
	},
	{
		.name = "rseq",
		.toggle = STS_TA,
		.settings = STS_3I | STS_4I | STS_5I
	},
	{
		.name = "pidfd_send_signal",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "io_uring_setup",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "io_uring_enter",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_6I
	},
	{
		.name = "io_uring_register",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_4I
	},
	{
		.name = "open_tree",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S
	},
	{
		.name = "move_mount",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2S | STS_3I | STS_4S | STS_5I
	},
	{
		.name = "fsopen",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "fsconfig",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2I | STS_3S | STS_5I
	},
	{
		.name = "fsmount",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "fspick",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "pidfd_open",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "clone3",
		.toggle = STS_TA,
		.settings = STS_3I
	},
	{
		.name = "close_range",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "openat2",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_5I
	},
	{
		.name = "pidfd_getfd",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "faccessat2",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3S | STS_4I | STS_5I
	},
	{
		.name = "process_madvise",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "epoll_pwait2",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "mount_setattr",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_2S | STS_3I | STS_5I
	},
	{
		.name = "quotactl_fd",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "landlock_create_ruleset",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "landlock_add_rule",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "landlock_restrict_self",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "memfd_secret",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "process_mrelease",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "futex_waitv",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "set_mempolicy_home_node",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "cachestat",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_5I
	},
	{
		.name = "fchmodat2",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3S | STS_4I | STS_5I
	},
	{
		.name = "map_shadow_stack",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "compat_rt_sigaction",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_5I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "compat_ioctl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "readv",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "writev",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "compat_recvfrom",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_6I
	},
	{
		.name = "compat_sendmsg",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "compat_recvmsg",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "compat_execve",
		.toggle = STS_TA,
		.settings = STS_1S
	},
	{
		.name = "compat_ptrace",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "compat_rt_sigpending",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "compat_rt_sigtimedwait_time64",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "compat_rt_sigqueueinfo",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "compat_sigaltstack",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "compat_timer_create",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "compat_mq_notify",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "compat_kexec_load",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "compat_waitid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "compat_set_robust_list",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "compat_get_robust_list",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "vmsplice",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "move_pages",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "compat_preadv64",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "compat_pwritev64",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "compat_rt_tgsigqueueinfo",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "compat_recvmmsg_time64",
		.toggle = STS_TA,
		.settings = STS_1I | STS_4I | STS_5I
	},
	{
		.name = "compat_sendmmsg",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_4I
	},
	{
		.name = "process_vm_readv",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I | STS_5I | STS_6I
	},
	{
		.name = "process_vm_writev",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_6I
	},
	{
		.name = "setsockopt",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5S | STS_6I
	},
	{
		.name = "getsockopt",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5S | STS_6I
	},
	{
		.name = "compat_io_setup",
		.toggle = STS_TA,
	},
	{
		.name = "compat_io_submit",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "compat_execveat",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2S
	},
	{
		.name = "compat_preadv64v2",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "compat_pwritev64v2",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_1I | STS_3I | STS_4I | STS_5I
	},

};

t_syscall i386_syscalls[385] = {
	{
		.name = "restart_syscall",

	},
	{
		.name = "exit",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "fork",

	},
	{
		.name = "read",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "write",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "open",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I | STS_3I
	},
	{
		.name = "close",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "waitpid",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "creat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "link",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2S
	},
	{
		.name = "unlink",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "execve",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S | STS_4S
	},
	{
		.name = "chdir",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "time",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "mknod",
		.toggle = STS_TA | STS_4,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "chmod",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "lchown16",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I | STS_3I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "stat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "lseek",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "getpid",

	},
	{
		.name = "mount",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1S | STS_2S | STS_3S | STS_4I
	},
	{
		.name = "oldumount",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "setuid16",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "getuid16",

	},
	{
		.name = "stime",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "ptrace",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "alarm",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "fstat",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "pause",
		.toggle = STS_1,
	},
	{
		.name = "utime",
		.toggle = STS_TA,
		.settings = STS_2S
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",

	},
	{
		.name = "access",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "nice",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "sync",

	},
	{
		.name = "kill",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "rename",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2S
	},
	{
		.name = "mkdir",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "rmdir",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "dup",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "pipe",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "times",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "brk",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setgid16",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "getgid16",
		.toggle = STS_1,
	},
	{
		.name = "signal",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "geteuid16",

	},
	{
		.name = "getegid16",

	},
	{
		.name = "acct",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "umount",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "ioctl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "fcntl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "setpgid",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "olduname",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "umask",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "chroot",
		.toggle = STS_1 | STS_2,
		.settings = STS_2S
	},
	{
		.name = "ustat",
		.toggle = STS_TA,
	},
	{
		.name = "dup2",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "getppid",

	},
	{
		.name = "getpgrp",

	},
	{
		.name = "setsid",

	},
	{
		.name = "sigaction",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "sgetmask",

	},
	{
		.name = "ssetmask",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "setreuid16",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "setregid16",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "sigsuspend",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "sigpending",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sethostname",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "setrlimit",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "old_getrlimit",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "getrusage",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "gettimeofday",
		.toggle = STS_TA,
	},
	{
		.name = "settimeofday",
		.toggle = STS_TA,
	},
	{
		.name = "getgroups16",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "setgroups16",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "old_select",
		.toggle = STS_1,
	},
	{
		.name = "symlink",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2S
	},
	{
		.name = "lstat",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "readlink",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2S | STS_3I
	},
	{
		.name = "uselib",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "swapon",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "reboot",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "old_readdir",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "old_mmap",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "munmap",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "truncate",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "ftruncate",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "fchmod",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "fchown16",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getpriority",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "setpriority",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "statfs",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S
	},
	{
		.name = "fstatfs",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "ioperm",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "socketcall",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "syslog",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I | STS_6I
	},
	{
		.name = "setitimer",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "getitimer",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "newstat",
		.toggle = STS_TA,
		.settings = STS_2S
	},
	{
		.name = "newlstat",
		.toggle = STS_TA,
		.settings = STS_2S
	},
	{
		.name = "newfstat",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "uname",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "iopl",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "vhangup",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",

	},
	{
		.name = "vm86old",
		.toggle = STS_1,
	},
	{
		.name = "wait4",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "swapoff",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "sysinfo",
		.toggle = STS_1,
	},
	{
		.name = "ipc",

	},
	{
		.name = "fsync",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sigreturn",

	},
	{
		.name = "clone",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "setdomainname",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "newuname",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "modify_ldt",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "adjtimex",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "mprotect",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "sigprocmask",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "init_module",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "delete_module",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "quotactl",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "getpgid",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "fchdir",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "bdflush",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "sysfs",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "personality",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "setfsuid16",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setfsgid16",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "llseek",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "getdents",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "select",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I
	},
	{
		.name = "flock",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "msync",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "readv",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "writev",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "getsid",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "fdatasync",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sysctl",
		.toggle = STS_1,
	},
	{
		.name = "mlock",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "munlock",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "mlockall",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "munlockall",

	},
	{
		.name = "sched_setparam",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "sched_getparam",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "sched_setscheduler",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "sched_getscheduler",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "sched_yield",
		.toggle = STS_1,
	},
	{
		.name = "sched_get_priority_max",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "sched_get_priority_min",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "sched_rr_get_interval",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "nanosleep",
		.toggle = STS_TA,
	},
	{
		.name = "mremap",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "setresuid16",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getresuid16",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "vm86",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "poll",
		.toggle = STS_TA | STS_4,
		.settings = STS_3I | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "setresgid16",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getresgid16",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "prctl",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "rt_sigreturn",
		.toggle = STS_1,
	},
	{
		.name = "rt_sigaction",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_5I
	},
	{
		.name = "rt_sigprocmask",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "rt_sigpending",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "rt_sigtimedwait",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "rt_sigqueueinfo",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "rt_sigsuspend",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "pread64",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_4I | STS_5I
	},
	{
		.name = "pwrite64",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3S | STS_4I | STS_5I
	},
	{
		.name = "chown16",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "getcwd",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "capget",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "capset",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "sigaltstack",
		.toggle = STS_TA,
	},
	{
		.name = "sendfile",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "vfork",
		.toggle = STS_1,
	},
	{
		.name = "getrlimit",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "mmap_pgoff",
		.toggle = STS_1,
	},
	{
		.name = "truncate64",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "ftruncate64",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "stat64",
		.toggle = STS_TA,
		.settings = STS_2S
	},
	{
		.name = "lstat64",
		.toggle = STS_TA,
		.settings = STS_2S
	},
	{
		.name = "fstat64",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "lchown",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "getuid",
		.toggle = STS_1,
	},
	{
		.name = "getgid",
		.toggle = STS_1,
	},
	{
		.name = "geteuid",
		.toggle = STS_1,
	},
	{
		.name = "getegid",
		.toggle = STS_1,
	},
	{
		.name = "setreuid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "setregid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "getgroups",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "setgroups",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "fchown",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "setresuid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getresuid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "setresgid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getresgid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "chown",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3I | STS_4I
	},
	{
		.name = "setuid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setgid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setfsuid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "setfsgid",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "pivot_root",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S
	},
	{
		.name = "mincore",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4S
	},
	{
		.name = "madvise",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "getdents64",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "fcntl64",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "gettid",
		.toggle = STS_1,
	},
	{
		.name = "readahead",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "setxattr",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2S | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "lsetxattr",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2S | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "fsetxattr",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "getxattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "lgetxattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "fgetxattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "listxattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "llistxattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S | STS_4I
	},
	{
		.name = "flistxattr",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "removexattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S
	},
	{
		.name = "lremovexattr",
		.toggle = STS_TA,
		.settings = STS_2S | STS_3S
	},
	{
		.name = "fremovexattr",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "tkill",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "sendfile64",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "futex",
		.toggle = STS_1,
	},
	{
		.name = "sched_setaffinity",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "sched_getaffinity",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "set_thread_area",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "get_thread_area",
		.toggle = STS_1 | STS_2,
	},
	{
		.name = "io_setup",
		.toggle = STS_TA,
		.settings = STS_3I
	},
	{
		.name = "io_destroy",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "io_getevents",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "io_submit",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "io_cancel",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I
	},
	{
		.name = "fadvise64",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "exit_group",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "lookup_dcookie",
		.toggle = STS_TA | STS_4,
		.settings = STS_3S | STS_4I
	},
	{
		.name = "epoll_create",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "epoll_ctl",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "epoll_wait",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "remap_file_pages",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "set_tid_address",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "timer_create",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "timer_settime",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "timer_gettime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "timer_getoverrun",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "timer_delete",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "clock_settime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "clock_gettime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "clock_getres",
		.toggle = STS_TA,
		.settings = STS_2I
	},
	{
		.name = "clock_nanosleep",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "statfs64",
		.toggle = STS_TA | STS_4,
		.settings = STS_2S | STS_3I
	},
	{
		.name = "fstatfs64",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "tgkill",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "utimes",
		.toggle = STS_TA,
		.settings = STS_2S
	},
	{
		.name = "fadvise64_64",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "not implemented",

	},
	{
		.name = "mbind",

	},
	{
		.name = "get_mempolicy",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "set_mempolicy",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "mq_open",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I | STS_3I
	},
	{
		.name = "mq_unlink",
		.toggle = STS_1,
		.settings = STS_1S
	},
	{
		.name = "mq_timedsend",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "mq_timedreceive",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "mq_notify",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "mq_getsetattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I
	},
	{
		.name = "kexec_load",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "waitid",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_5I
	},
	{
		.name = "not implemented",
		.toggle = STS_1,
	},
	{
		.name = "add_key",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_5I | STS_6I
	},
	{
		.name = "request_key",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3S | STS_4S | STS_5I
	},
	{
		.name = "keyctl",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "ioprio_set",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "ioprio_get",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "inotify_init",

	},
	{
		.name = "inotify_add_watch",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S
	},
	{
		.name = "inotify_rm_watch",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "migrate_pages",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "openat",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2S | STS_3I | STS_4I
	},
	{
		.name = "mkdirat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "mknodat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "fchownat",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "futimesat",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "fstatat64",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_5I
	},
	{
		.name = "unlinkat",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "renameat",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3S | STS_4I | STS_5S
	},
	{
		.name = "linkat",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S | STS_4I | STS_5S | STS_6I
	},
	{
		.name = "symlinkat",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I | STS_3S
	},
	{
		.name = "readlinkat",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2S | STS_3S | STS_4I
	},
	{
		.name = "fchmodat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "faccessat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_3I
	},
	{
		.name = "pselect6",

	},
	{
		.name = "ppoll",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_5I
	},
	{
		.name = "unshare",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "set_robust_list",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "get_robust_list",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "splice",

	},
	{
		.name = "sync_file_range",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "tee",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "vmsplice",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_5I
	},
	{
		.name = "move_pages",
		.toggle = STS_1,
	},
	{
		.name = "getcpu",
		.toggle = STS_TA | STS_4,
	},
	{
		.name = "epoll_pwait",
		.toggle = STS_1,
	},
	{
		.name = "utimensat",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2S | STS_4I
	},
	{
		.name = "signalfd",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "timerfd_create",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "eventfd",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "fallocate",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "timerfd_settime",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "timerfd_gettime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "signalfd4",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "eventfd2",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "epoll_create1",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "dup3",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I | STS_4I
	},
	{
		.name = "pipe2",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "inotify_init1",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "preadv",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "pwritev",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "rt_tgsigqueueinfo",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "perf_event_open",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "recvmmsg",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "fanotify_init",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "fanotify_mark",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2I | STS_4I | STS_5S
	},
	{
		.name = "prlimit64",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "name_to_handle_at",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2S | STS_4I | STS_5I
	},
	{
		.name = "open_by_handle_at",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "clock_adjtime",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I
	},
	{
		.name = "syncfs",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "sendmmsg",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "setns",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "process_vm_readv",
		.toggle = STS_1,
	},
	{
		.name = "process_vm_writev",
		.toggle = STS_1,
	},
	{
		.name = "kcmp",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I | STS_6I
	},
	{
		.name = "finit_module",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3S | STS_4I
	},
	{
		.name = "sched_setattr",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "sched_getattr",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I | STS_4I
	},
	{
		.name = "renameat2",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2S | STS_3I | STS_4S | STS_5I
	},
	{
		.name = "seccomp",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3S
	},
	{
		.name = "getrandom",
		.toggle = STS_TA,
		.settings = STS_1S | STS_2I | STS_3I
	},
	{
		.name = "memfd_create",
		.toggle = STS_1 | STS_2,
		.settings = STS_1S | STS_2I
	},
	{
		.name = "bpf",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "execveat",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_1I | STS_2S | STS_3S | STS_4S | STS_5I
	},
	{
		.name = "socket",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "socketpair",
		.toggle = STS_TA | STS_4,
		.settings = STS_1I | STS_2I | STS_3I | STS_4I
	},
	{
		.name = "bind",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "connect",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "listen",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "accept4",
		.toggle = STS_TA,
		.settings = STS_2I | STS_4I | STS_5I
	},
	{
		.name = "getsockopt",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5S | STS_6I
	},
	{
		.name = "setsockopt",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3I | STS_4I | STS_5S | STS_6I
	},
	{
		.name = "getsockname",
		.toggle = STS_TA | STS_4,
		.settings = STS_2I | STS_4I
	},
	{
		.name = "getpeername",
		.toggle = STS_TA,
		.settings = STS_1I | STS_3I
	},
	{
		.name = "sendto",

	},
	{
		.name = "sendmsg",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "recvfrom",

	},
	{
		.name = "recvmsg",
		.toggle = STS_TA,
		.settings = STS_1I
	},
	{
		.name = "shutdown",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "userfaultfd",
		.toggle = STS_1,
		.settings = STS_1I
	},
	{
		.name = "membarrier",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
	{
		.name = "mlock2",
		.toggle = STS_TA,
		.settings = STS_1I | STS_2I | STS_3I
	},
	{
		.name = "copy_file_range",

	},
	{
		.name = "preadv2",
		.toggle = STS_1,
	},
	{
		.name = "pwritev2",
		.toggle = STS_1,
	},
	{
		.name = "pkey_mprotect",
		.toggle = STS_TA | STS_4 | STS_5,
		.settings = STS_2I | STS_3I | STS_4I | STS_5I
	},
	{
		.name = "pkey_alloc",
		.toggle = STS_TA,
		.settings = STS_2I | STS_3I
	},
	{
		.name = "pkey_free",
		.toggle = STS_1 | STS_2,
		.settings = STS_2I
	},
	{
		.name = "statx",
		.toggle = STS_TA | STS_TAXT,
		.settings = STS_2I | STS_3S
	},
	{
		.name = "arch_prctl",
		.toggle = STS_1 | STS_2,
		.settings = STS_1I | STS_2I
	},
};
