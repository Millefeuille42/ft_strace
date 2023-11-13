//
// Created by millefeuille on 9/19/23.
//

#include "ft_log.h"

void ft_lognbr_in_between(
	const enum log_level level,
	const char* prefix,
	const long n,
	const char* suffix,
	char const no_header
) {
	if (level > LOG_LEVEL) return;
	if (!no_header) print_level(level);

	ft_putstr(prefix);
	ft_putnbr(n);
	ft_putstr(suffix);
}
