//
// Created by millefeuille on 10/17/23.
//

#include "ft_strace.h"

static int print_string_from_child(const int pid, const long address, const size_t read_size) {
	// TODO protect all of this
	flush(1);
	ft_lognbr_in_between(NONE, "/proc/", pid, "/mem", 1);

	const int fd = open(get_buffer(1), O_RDONLY);
	if (errno) {
		ft_bzero(get_buffer(1), FT_PRINT_BUFFER_SIZE);
		*get_cursor(1) = 0;
		log_error("open");
		return 1;
	}
	ft_bzero(get_buffer(1), FT_PRINT_BUFFER_SIZE);
	*get_cursor(1) = 0;

	lseek(fd, address, SEEK_SET);
	if (errno) {
		close(fd);
		log_error("lseek");
		return 1;
	}

	char buffer[STRACE_MAX_STRING_SIZE + 1];
	ft_bzero(buffer, sizeof(buffer));
	size_t printed_count = 0;

	for (int exit = 0; !exit;) {
		read(fd, buffer, sizeof(buffer) - 1);
		if (errno) {
			close(fd);
			log_error("read_loop");
			return 1;
		}

		if (printed_count + ft_strlen(buffer) > STRACE_MAX_STRING_SIZE) {
			ft_putstr_escape(buffer, STRACE_MAX_STRING_SIZE - printed_count);
			ft_putstr("...");
			break;
		}
		printed_count += ft_strlen(buffer);
		ft_putstr_escape(buffer, read_size);
		for (size_t pos = 0; pos < sizeof(buffer) - 1; pos++) if (buffer[pos] == '\0') exit = 1;

		ft_bzero(buffer, sizeof(buffer));
	}

	close(fd);
	return 0;
}

void print_registry(const t_syscall* syscall, const int registry_num, void* registry, const int pid) {
	if (!STRACE_HAS_FLAG(syscall->toggle, registry_num)) return;

	const int least_position = find_least_significant_bit_position(registry_num);
	if (least_position && registry_num != STS_A)
		ft_putstr(", ");

	int offset = 1 << 2 * least_position;
	// Check for S bit (is string)
	if (STRACE_HAS_FLAG(syscall->settings, offset)) {
		ft_putstr("\"");
		print_string_from_child(pid, (long)registry, syscall->read_size);
		ft_putstr("\"");
		return;
	}

	offset <<= 1;
	// Check for I bit (is integer)
	if (STRACE_HAS_FLAG(syscall->settings, offset)) {
		ft_putnbr((long)registry);
		return;
	}

	// Fallback, print pointer
	if (!registry) ft_putstr("NULL");
	else {
		ft_putstr("0x");
		ft_putnbr_base((size_t)registry, "0123456789abcdef", 16);
	}
}

void print_syscall_info(const t_syscall* syscall, const struct user_regs_struct* regs, const int pid) {
	ft_putstr(syscall->name);
	ft_putstr("(");
	if (STRACE_HAS_FLAG(syscall->toggle, STS_1)) print_registry(syscall, STS_1, (void *)regs->rdi, pid);
	if (STRACE_HAS_FLAG(syscall->toggle, STS_2)) print_registry(syscall, STS_2, (void *)regs->rsi, pid);
	if (STRACE_HAS_FLAG(syscall->toggle, STS_3)) print_registry(syscall, STS_3, (void *)regs->rdx, pid);
	if (STRACE_HAS_FLAG(syscall->toggle, STS_4)) print_registry(syscall, STS_4, (void *)regs->r10, pid);
	if (STRACE_HAS_FLAG(syscall->toggle, STS_5)) print_registry(syscall, STS_5, (void *)regs->r8, pid);
	if (STRACE_HAS_FLAG(syscall->toggle, STS_6)) print_registry(syscall, STS_6, (void *)regs->r9, pid);
	ft_putstr(")");
}


void print_signal_info(const siginfo_t* siginfo) {
	ft_logstr(INFO, "SIGNAL <");
	const char* signal_name = (size_t)siginfo->si_signo > sizeof(signals) / sizeof(signals[0])
		                          ? "UNKNOWN"
		                          : signals[siginfo->si_signo];
	ft_logstr_no_header(INFO, signal_name);
	ft_lognbr_in_between(INFO, "> {si_signo=", siginfo->si_signo, ", ", 1);
	ft_lognbr_in_between(INFO, "si_code==", siginfo->si_code, ", ", 1);
	ft_lognbr_in_between(INFO, "si_pid==", siginfo->si_pid, ", ", 1);
	ft_lognbr_in_between(INFO, "si_uid==", siginfo->si_uid, "}\n", 1);
}

void print_signal_stop(const siginfo_t* siginfo) {
	ft_logstr(INFO, "child stopped due to signal <");
	const char* signal_name = (size_t)siginfo->si_signo > sizeof(signals) / sizeof(signals[0])
		                          ? "UNKNOWN"
		                          : signals[siginfo->si_signo];
	ft_logstr_no_header(INFO, signal_name);
	ft_lognbr_in_between(INFO, "> (", siginfo->si_signo, ")\n", 1);
}
