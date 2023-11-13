//
// Created by millefeuille on 9/19/23.
//

#include "ft_log.h"

void ft_lognbr(const enum log_level level, const long n) {
	if (level > LOG_LEVEL) return;
	print_level(level);

	ft_putnbr(n);
}
