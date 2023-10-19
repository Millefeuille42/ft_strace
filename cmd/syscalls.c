//
// Created by millefeuille on 9/20/23.
//

#include "syscalls.h"

t_syscall syscall_unknown = (t_syscall){.name="UNKNOWN", .toggle=STS_TA};

// TODO add others syscall management
t_syscall syscalls[400] = {
		{
				.name = "read",
				.toggle = STS_TA,
				.settings = STS_1I | STS_3I | STS_AI
		},
		{
				.name = "write",
				.toggle = STS_TA,
				.settings = STS_1I | STS_2S | STS_3I | STS_AI
		},
		{
				.name = "open",
				.toggle = STS_TA,
				.settings = STS_1S | STS_2I | STS_3I | STS_AI
		},
		{
				.name = "close",
				.toggle = STS_1 | STS_A,
				.settings = STS_1I | STS_AI
		},
		{
				.name = "stat",
				.toggle = STS_1 | STS_2 | STS_A,
				.settings = STS_1S | STS_AI
		},
		{
				.name = "fstat",
				.toggle = STS_1 | STS_2 | STS_A,
				.settings = STS_1I | STS_AI
		},
		{
				.name = "lstat",
				.toggle = STS_1 | STS_2 | STS_A,
				.settings = STS_1S | STS_AI
		},
		{
				.name = "poll_time64",
				.toggle = STS_TA
		},
		{
				.name = "lseek",
				.toggle = STS_TA,
				.settings = STS_1I | STS_2I | STS_3I | STS_AI
		},
		{
				.name = "mmap",
				.toggle = STS_TA | STS_TAXT,
				.settings = STS_2I|STS_3I|STS_XT_4I|STS_XT_5I|STS_XT_6I
		},
		{
				.name = "mprotect",
				.toggle = STS_TA,
				.settings = STS_2I | STS_3I | STS_AI
		},
		{
				.name = "munmap",
				.toggle = STS_1 | STS_2 | STS_A,
				.settings = STS_2I | STS_AI
		},
		{
				.name = "brk",
				.toggle = STS_1 | STS_A,
		},
		{
				.name = "rt_sigaction",
				.toggle = STS_TA
		},
		{
				.name = "rt_sigprocmask",
				.toggle = STS_TA
		},
		{
				.name = "rt_sigreturn",
				.toggle = STS_TA
		},
		{
				.name = "ioctl",
				.toggle = STS_TA
		},
		{
				.name = "pread",
				.toggle = STS_TA|STS_4,
				.settings = STS_1I|STS_3I|STS_XT_4I|STS_AI
		},
		{
				.name = "pwrite",
				.toggle = STS_TA
		},
		{
				.name = "readv",
				.toggle = STS_TA
		},
		{
				.name = "writev",
				.toggle = STS_TA
		},
		{
				.name = "access",
				.toggle = STS_1 | STS_2 | STS_A,
				.settings = STS_1S | STS_2I | STS_AI,
		},
		{
				.name = "pipe",
				.toggle = STS_TA
		},
		{
				.name = "select",
				.toggle = STS_TA
		},
		{
				.name = "sched_yield",
				.toggle = STS_TA
		},
		{
				.name = "mremap",
				.toggle = STS_TA
		},
		{
				.name = "msync",
				.toggle = STS_TA
		},
		{
				.name = "mincore",
				.toggle = STS_TA
		},
		{
				.name = "madvise",
				.toggle = STS_TA
		},
		{
				.name = "shmget",
				.toggle = STS_TA
		},
		{
				.name = "shmat",
				.toggle = STS_TA
		},
		{
				.name = "shmctl",
				.toggle = STS_TA
		},
		{
				.name = "dup",
				.toggle = STS_TA
		},
		{
				.name = "dup2",
				.toggle = STS_TA
		},
		{
				.name = "pause",
				.toggle = STS_TA
		},
		{
				.name = "nanosleep_time64",
				.toggle = STS_TA
		},
		{
				.name = "getitimer",
				.toggle = STS_TA
		},
		{
				.name = "alarm",
				.toggle = STS_TA
		},
		{
				.name = "setitimer",
				.toggle = STS_TA
		},
		{
				.name = "getpid",
				.toggle = STS_TA
		},
		{
				.name = "sendfile64",
				.toggle = STS_TA
		},
		{
				.name = "socket",
				.toggle = STS_TA
		},
		{
				.name = "connect",
				.toggle = STS_TA
		},
		{
				.name = "accept",
				.toggle = STS_TA
		},
		{
				.name = "sendto",
				.toggle = STS_TA
		},
		{
				.name = "recvfrom",
				.toggle = STS_TA
		},
		{
				.name = "sendmsg",
				.toggle = STS_TA
		},
		{
				.name = "recvmsg",
				.toggle = STS_TA
		},
		{
				.name = "shutdown",
				.toggle = STS_TA
		},
		{
				.name = "bind",
				.toggle = STS_TA
		},
		{
				.name = "listen",
				.toggle = STS_TA
		},
		{
				.name = "getsockname",
				.toggle = STS_TA
		},
		{
				.name = "getpeername",
				.toggle = STS_TA
		},
		{
				.name = "socketpair",
				.toggle = STS_TA
		},
		{
				.name = "setsockopt",
				.toggle = STS_TA
		},
		{
				.name = "getsockopt",
				.toggle = STS_TA
		},
		{
				.name = "clone",
				.toggle = STS_TA
		},
		{
				.name = "fork",
				.toggle = STS_TA
		},
		{
				.name = "vfork",
				.toggle = STS_TA
		},
		{
				.name = "execve",
				.toggle = STS_TA
		},
		{
				.name = "exit",
				.toggle = STS_1,
				.settings = STS_1S
		},
		{
				.name = "wait4",
				.toggle = STS_TA
		},
		{
				.name = "kill",
				.toggle = STS_TA
		},
		{
				.name = "uname",
				.toggle = STS_TA
		},
		{
				.name = "semget",
				.toggle = STS_TA
		},
		{
				.name = "semop",
				.toggle = STS_TA
		},
		{
				.name = "semctl",
				.toggle = STS_TA
		},
		{
				.name = "shmdt",
				.toggle = STS_TA
		},
		{
				.name = "msgget",
				.toggle = STS_TA
		},
		{
				.name = "msgsnd",
				.toggle = STS_TA
		},
		{
				.name = "msgrcv",
				.toggle = STS_TA
		},
		{
				.name = "msgctl",
				.toggle = STS_TA
		},
		{
				.name = "fcntl",
				.toggle = STS_TA
		},
		{
				.name = "flock",
				.toggle = STS_TA
		},
		{
				.name = "fsync",
				.toggle = STS_TA
		},
		{
				.name = "fdatasync",
				.toggle = STS_TA
		},
		{
				.name = "truncate",
				.toggle = STS_TA
		},
		{
				.name = "ftruncate",
				.toggle = STS_TA
		},
		{
				.name = "getdents",
				.toggle = STS_TA
		},
		{
				.name = "getcwd",
				.toggle = STS_TA
		},
		{
				.name = "chdir",
				.toggle = STS_TA
		},
		{
				.name = "fchdir",
				.toggle = STS_TA
		},
		{
				.name = "rename",
				.toggle = STS_TA
		},
		{
				.name = "mkdir",
				.toggle = STS_TA
		},
		{
				.name = "rmdir",
				.toggle = STS_TA
		},
		{
				.name = "creat",
				.toggle = STS_TA
		},
		{
				.name = "link",
				.toggle = STS_TA
		},
		{
				.name = "unlink",
				.toggle = STS_TA
		},
		{
				.name = "symlink",
				.toggle = STS_TA
		},
		{
				.name = "readlink",
				.toggle = STS_TA
		},
		{
				.name = "chmod",
				.toggle = STS_TA
		},
		{
				.name = "fchmod",
				.toggle = STS_TA
		},
		{
				.name = "chown",
				.toggle = STS_TA
		},
		{
				.name = "fchown",
				.toggle = STS_TA
		},
		{
				.name = "chown",
				.toggle = STS_TA
		},
		{
				.name = "umask",
				.toggle = STS_TA
		},
		{
				.name = "gettimeofday",
				.toggle = STS_TA
		},
		{
				.name = "getrlimit",
				.toggle = STS_TA
		},
		{
				.name = "getrusage",
				.toggle = STS_TA
		},
		{
				.name = "sysinfo",
				.toggle = STS_TA
		},
		{
				.name = "times",
				.toggle = STS_TA
		},
		{
				.name = "ptrace",
				.toggle = STS_TA
		},
		{
				.name = "getuid",
				.toggle = STS_TA
		},
		{
				.name = "syslog",
				.toggle = STS_TA
		},
		{
				.name = "getgid",
				.toggle = STS_TA
		},
		{
				.name = "setuid",
				.toggle = STS_TA
		},
		{
				.name = "setgid",
				.toggle = STS_TA
		},
		{
				.name = "geteuid",
				.toggle = STS_TA
		},
		{
				.name = "getegid",
				.toggle = STS_TA
		},
		{
				.name = "setpgid",
				.toggle = STS_TA
		},
		{
				.name = "getppid",
				.toggle = STS_TA
		},
		{
				.name = "getpgrp",
				.toggle = STS_TA
		},
		{
				.name = "setsid",
				.toggle = STS_TA
		},
		{
				.name = "setreuid",
				.toggle = STS_TA
		},
		{
				.name = "setregid",
				.toggle = STS_TA
		},
		{
				.name = "getgroups",
				.toggle = STS_TA
		},
		{
				.name = "setgroups",
				.toggle = STS_TA
		},
		{
				.name = "setresuid",
				.toggle = STS_TA
		},
		{
				.name = "getresuid",
				.toggle = STS_TA
		},
		{
				.name = "setresgid",
				.toggle = STS_TA
		},
		{
				.name = "getresgid",
				.toggle = STS_TA
		},
		{
				.name = "getpgid",
				.toggle = STS_TA
		},
		{
				.name = "setfsuid",
				.toggle = STS_TA
		},
		{
				.name = "setfsgid",
				.toggle = STS_TA
		},
		{
				.name = "getsid",
				.toggle = STS_TA
		},
		{
				.name = "capget",
				.toggle = STS_TA
		},
		{
				.name = "capset",
				.toggle = STS_TA
		},
		{
				.name = "rt_sigpending",
				.toggle = STS_TA
		},
		{
				.name = "rt_sigtimedwait_time64",
				.toggle = STS_TA
		},
		{
				.name = "rt_sigqueueinfo",
				.toggle = STS_TA
		},
		{
				.name = "rt_sigsuspend",
				.toggle = STS_TA
		},
		{
				.name = "sigaltstack",
				.toggle = STS_TA
		},
		{
				.name = "utime",
				.toggle = STS_TA
		},
		{
				.name = "mknod",
				.toggle = STS_TA
		},
		{
				.name = "uselib",
				.toggle = STS_TA
		},
		{
				.name = "personality",
				.toggle = STS_TA
		},
		{
				.name = "ustat",
				.toggle = STS_TA
		},
		{
				.name = "statfs",
				.toggle = STS_TA
		},
		{
				.name = "fstatfs",
				.toggle = STS_TA
		},
		{
				.name = "sysfs",
				.toggle = STS_TA
		},
		{
				.name = "getpriority",
				.toggle = STS_TA
		},
		{
				.name = "setpriority",
				.toggle = STS_TA
		},
		{
				.name = "sched_setparam",
				.toggle = STS_TA
		},
		{
				.name = "sched_getparam",
				.toggle = STS_TA
		},
		{
				.name = "sched_setscheduler",
				.toggle = STS_TA
		},
		{
				.name = "sched_getscheduler",
				.toggle = STS_TA
		},
		{
				.name = "sched_get_priority_max",
				.toggle = STS_TA
		},
		{
				.name = "sched_get_priority_min",
				.toggle = STS_TA
		},
		{
				.name = "sched_rr_get_interval_time64",
				.toggle = STS_TA
		},
		{
				.name = "mlock",
				.toggle = STS_TA
		},
		{
				.name = "munlock",
				.toggle = STS_TA
		},
		{
				.name = "mlockall",
				.toggle = STS_TA
		},
		{
				.name = "munlockall",
				.toggle = STS_TA
		},
		{
				.name = "vhangup",
				.toggle = STS_TA
		},
		{
				.name = "modify_ldt",
				.toggle = STS_TA
		},
		{
				.name = "pivotroot",
				.toggle = STS_TA
		},
		{
				.name = "sysctl",
				.toggle = STS_TA
		},
		{
				.name = "prctl",
				.toggle = STS_TA
		},
		{
				.name = "arch_prctl",
				.toggle = STS_TA
		},
		{
				.name = "adjtimex64",
				.toggle = STS_TA
		},
		{
				.name = "setrlimit",
				.toggle = STS_TA
		},
		{
				.name = "chroot",
				.toggle = STS_TA
		},
		{
				.name = "sync",
				.toggle = STS_TA
		},
		{
				.name = "acct",
				.toggle = STS_TA
		},
		{
				.name = "settimeofday",
				.toggle = STS_TA
		},
		{
				.name = "mount",
				.toggle = STS_TA
		},
		{
				.name = "umount2",
				.toggle = STS_TA
		},
		{
				.name = "swapon",
				.toggle = STS_TA
		},
		{
				.name = "swapoff",
				.toggle = STS_TA
		},
		{
				.name = "reboot",
				.toggle = STS_TA
		},
		{
				.name = "sethostname",
				.toggle = STS_TA
		},
		{
				.name = "setdomainname",
				.toggle = STS_TA
		},
		{
				.name = "iopl",
				.toggle = STS_TA
		},
		{
				.name = "ioperm",
				.toggle = STS_TA
		},
		{
				.name = "create_module",
				.toggle = STS_TA
		},
		{
				.name = "init_module",
				.toggle = STS_TA
		},
		{
				.name = "delete_module",
				.toggle = STS_TA
		},
		{
				.name = "get_kernel_syms",
				.toggle = STS_TA
		},
		{
				.name = "query_module",
				.toggle = STS_TA
		},
		{
				.name = "quotactl",
				.toggle = STS_TA
		},
		{
				.name = "nfsservctl",
				.toggle = STS_TA
		},
		{
				.name = "getpmsg",
				.toggle = STS_TA
		},
		{
				.name = "putpmsg",
				.toggle = STS_TA
		},
		{
				.name = "afs_syscall",
				.toggle = STS_TA
		},
		{
				.name = "tuxcall",
				.toggle = STS_TA
		},
		{
				.name = "security",
				.toggle = STS_TA
		},
		{
				.name = "gettid",
				.toggle = STS_TA
		},
		{
				.name = "readahead",
				.toggle = STS_TA
		},
		{
				.name = "setxattr",
				.toggle = STS_TA
		},
		{
				.name = "setxattr",
				.toggle = STS_TA
		},
		{
				.name = "fsetxattr",
				.toggle = STS_TA
		},
		{
				.name = "getxattr",
				.toggle = STS_TA
		},
		{
				.name = "getxattr",
				.toggle = STS_TA
		},
		{
				.name = "fgetxattr",
				.toggle = STS_TA
		},
		{
				.name = "listxattr",
				.toggle = STS_TA
		},
		{
				.name = "listxattr",
				.toggle = STS_TA
		},
		{
				.name = "flistxattr",
				.toggle = STS_TA
		},
		{
				.name = "removexattr",
				.toggle = STS_TA
		},
		{
				.name = "removexattr",
				.toggle = STS_TA
		},
		{
				.name = "fremovexattr",
				.toggle = STS_TA
		},
		{
				.name = "tkill",
				.toggle = STS_TA
		},
		{
				.name = "time",
				.toggle = STS_TA
		},
		{
				.name = "futex_time64",
				.toggle = STS_TA
		},
		{
				.name = "sched_setaffinity",
				.toggle = STS_TA
		},
		{
				.name = "sched_getaffinity",
				.toggle = STS_TA
		},
		{
				.name = "set_thread_area",
				.toggle = STS_TA
		},
		{
				.name = "io_setup",
				.toggle = STS_TA
		},
		{
				.name = "io_destroy",
				.toggle = STS_TA
		},
		{
				.name = "io_getevents_time64",
				.toggle = STS_TA
		},
		{
				.name = "io_submit",
				.toggle = STS_TA
		},
		{
				.name = "io_cancel",
				.toggle = STS_TA
		},
		{
				.name = "get_thread_area",
				.toggle = STS_TA
		},
		{
				.name = "lookup_dcookie",
				.toggle = STS_TA
		},
		{
				.name = "epoll_create",
				.toggle = STS_TA
		},
		{
				.name = "printargs",
				.toggle = STS_TA
		},
		{
				.name = "printargs",
				.toggle = STS_TA
		},
		{
				.name = "remap_file_pages",
				.toggle = STS_TA
		},
		{
				.name = "getdents64",
				.toggle = STS_TA
		},
		{
				.name = "set_tid_address",
				.toggle = STS_TA
		},
		{
				.name = "restart_syscall",
				.toggle = STS_TA
		},
		{
				.name = "semtimedop_time64",
				.toggle = STS_TA
		},
		{
				.name = "fadvise64",
				.toggle = STS_TA
		},
		{
				.name = "timer_create",
				.toggle = STS_TA
		},
		{
				.name = "timer_settime64",
				.toggle = STS_TA
		},
		{
				.name = "timer_gettime64",
				.toggle = STS_TA
		},
		{
				.name = "timer_getoverrun",
				.toggle = STS_TA
		},
		{
				.name = "timer_delete",
				.toggle = STS_TA
		},
		{
				.name = "clock_settime64",
				.toggle = STS_TA
		},
		{
				.name = "clock_gettime64",
				.toggle = STS_TA
		},
		{
				.name = "clock_getres_time64",
				.toggle = STS_TA
		},
		{
				.name = "clock_nanosleep_time64",
				.toggle = STS_TA
		},
		{
				.name = "exit_group",
				.toggle = STS_1,
				.settings = STS_1I
		},
		{
				.name = "epoll_wait",
				.toggle = STS_TA
		},
		{
				.name = "epoll_ctl",
				.toggle = STS_TA
		},
		{
				.name = "tgkill",
				.toggle = STS_TA
		},
		{
				.name = "utimes",
				.toggle = STS_TA
		},
		{
				.name = "vserver",
				.toggle = STS_TA
		},
		{
				.name = "mbind",
				.toggle = STS_TA
		},
		{
				.name = "set_mempolicy",
				.toggle = STS_TA
		},
		{
				.name = "get_mempolicy",
				.toggle = STS_TA
		},
		{
				.name = "mq_open",
				.toggle = STS_TA
		},
		{
				.name = "mq_unlink",
				.toggle = STS_TA
		},
		{
				.name = "mq_timedsend_time64",
				.toggle = STS_TA
		},
		{
				.name = "mq_timedreceive_time64",
				.toggle = STS_TA
		},
		{
				.name = "mq_notify",
				.toggle = STS_TA
		},
		{
				.name = "mq_getsetattr",
				.toggle = STS_TA
		},
		{
				.name = "kexec_load",
				.toggle = STS_TA
		},
		{
				.name = "waitid",
				.toggle = STS_TA
		},
		{
				.name = "add_key",
				.toggle = STS_TA
		},
		{
				.name = "request_key",
				.toggle = STS_TA
		},
		{
				.name = "keyctl",
				.toggle = STS_TA
		},
		{
				.name = "ioprio_set",
				.toggle = STS_TA
		},
		{
				.name = "ioprio_get",
				.toggle = STS_TA
		},
		{
				.name = "inotify_init",
				.toggle = STS_TA
		},
		{
				.name = "inotify_add_watch",
				.toggle = STS_TA
		},
		{
				.name = "inotify_rm_watch",
				.toggle = STS_TA
		},
		{
				.name = "migrate_pages",
				.toggle = STS_TA
		},
		{
				.name = "openat",
				.toggle = STS_TA,
				.settings = STS_1I | STS_2S | STS_3I | STS_AI,
		},
		{
				.name = "mkdirat",
				.toggle = STS_TA
		},
		{
				.name = "mknodat",
				.toggle = STS_TA
		},
		{
				.name = "fchownat",
				.toggle = STS_TA
		},
		{
				.name = "futimesat",
				.toggle = STS_TA
		},
		{
				.name = "newfstatat",
				.toggle = STS_TA|STS_4,
				.settings = STS_1I|STS_2S|STS_XT_4I,
		},
		{
				.name = "unlinkat",
				.toggle = STS_TA
		},
		{
				.name = "renameat",
				.toggle = STS_TA
		},
		{
				.name = "linkat",
				.toggle = STS_TA
		},
		{
				.name = "symlinkat",
				.toggle = STS_TA
		},
		{
				.name = "readlinkat",
				.toggle = STS_TA
		},
		{
				.name = "fchmodat",
				.toggle = STS_TA
		},
		{
				.name = "faccessat",
				.toggle = STS_TA
		},
		{
				.name = "pselect6_time64",
				.toggle = STS_TA
		},
		{
				.name = "ppoll_time64",
				.toggle = STS_TA
		},
		{
				.name = "unshare",
				.toggle = STS_TA
		},
		{
				.name = "set_robust_list",
				.toggle = STS_TA
		},
		{
				.name = "get_robust_list",
				.toggle = STS_TA
		},
		{
				.name = "splice",
				.toggle = STS_TA
		},
		{
				.name = "tee",
				.toggle = STS_TA
		},
		{
				.name = "sync_file_range",
				.toggle = STS_TA
		},
		{
				.name = "vmsplice",
				.toggle = STS_TA
		},
		{
				.name = "move_pages",
				.toggle = STS_TA
		},
		{
				.name = "utimensat_time64",
				.toggle = STS_TA
		},
		{
				.name = "epoll_pwait",
				.toggle = STS_TA
		},
		{
				.name = "signalfd",
				.toggle = STS_TA
		},
		{
				.name = "timerfd_create",
				.toggle = STS_TA
		},
		{
				.name = "eventfd",
				.toggle = STS_TA
		},
		{
				.name = "fallocate",
				.toggle = STS_TA
		},
		{
				.name = "timerfd_settime64",
				.toggle = STS_TA
		},
		{
				.name = "timerfd_gettime64",
				.toggle = STS_TA
		},
		{
				.name = "accept4",
				.toggle = STS_TA
		},
		{
				.name = "signalfd4",
				.toggle = STS_TA
		},
		{
				.name = "eventfd2",
				.toggle = STS_TA
		},
		{
				.name = "epoll_create1",
				.toggle = STS_TA
		},
		{
				.name = "dup3",
				.toggle = STS_TA
		},
		{
				.name = "pipe2",
				.toggle = STS_TA
		},
		{
				.name = "inotify_init1",
				.toggle = STS_TA
		},
		{
				.name = "preadv",
				.toggle = STS_TA
		},
		{
				.name = "pwritev",
				.toggle = STS_TA
		},
		{
				.name = "rt_tgsigqueueinfo",
				.toggle = STS_TA
		},
		{
				.name = "perf_event_open",
				.toggle = STS_TA
		},
		{
				.name = "recvmmsg_time64",
				.toggle = STS_TA
		},
		{
				.name = "fanotify_init",
				.toggle = STS_TA
		},
		{
				.name = "fanotify_mark",
				.toggle = STS_TA
		},
		{
				.name = "prlimit64",
				.toggle = STS_TA
		},
		{
				.name = "name_to_handle_at",
				.toggle = STS_TA
		},
		{
				.name = "open_by_handle_at",
				.toggle = STS_TA
		},
		{
				.name = "clock_adjtime64",
				.toggle = STS_TA
		},
		{
				.name = "syncfs",
				.toggle = STS_TA
		},
		{
				.name = "sendmmsg",
				.toggle = STS_TA
		},
		{
				.name = "setns",
				.toggle = STS_TA
		},
		{
				.name = "getcpu",
				.toggle = STS_TA
		},
		{
				.name = "process_vm_readv",
				.toggle = STS_TA
		},
		{
				.name = "process_vm_writev",
				.toggle = STS_TA
		},
		{
				.name = "kcmp",
				.toggle = STS_TA
		},
		{
				.name = "finit_module",
				.toggle = STS_TA
		},
		{
				.name = "sched_setattr",
				.toggle = STS_TA
		},
		{
				.name = "sched_getattr",
				.toggle = STS_TA
		},
		{
				.name = "renameat2",
				.toggle = STS_TA
		},
		{
				.name = "seccomp",
				.toggle = STS_TA
		},
		{
				.name = "getrandom",
				.toggle = STS_TA
		},
		{
				.name = "memfd_create",
				.toggle = STS_TA
		},
		{
				.name = "kexec_file_load",
				.toggle = STS_TA
		},
		{
				.name = "bpf",
				.toggle = STS_TA
		},
		{
				.name = "execveat",
				.toggle = STS_TA
		},
		{
				.name = "userfaultfd",
				.toggle = STS_TA
		},
		{
				.name = "membarrier",
				.toggle = STS_TA
		},
		{
				.name = "mlock2",
				.toggle = STS_TA
		},
		{
				.name = "copy_file_range",
				.toggle = STS_TA
		},
		{
				.name = "preadv2",
				.toggle = STS_TA
		},
		{
				.name = "pwritev2",
				.toggle = STS_TA
		},
		{
				.name = "pkey_mprotect",
				.toggle = STS_TA
		},
		{
				.name = "pkey_alloc",
				.toggle = STS_TA
		},
		{
				.name = "pkey_free",
				.toggle = STS_TA
		},
		{
				.name = "statx",
				.toggle = STS_TA
		},
		{
				.name = "io_pgetevents_time64",
				.toggle = STS_TA
		},
		{
				.name = "rseq",
				.toggle = STS_TA
		},
};
