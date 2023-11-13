//
// Created by millefeuille on 9/19/23.
//

#include "ft_log.h"

void ft_logstr_no_header(const enum log_level level, const char *str) {
	if (level > LOG_LEVEL) return;
	if (level == ERROR) {
		ft_fputstr(str, 2);
		return;
	}
	ft_putstr(str);
}

void ft_logstr(const enum log_level level, const char *str) {
	if (level > LOG_LEVEL) return;
	print_level(level);
	if (level == ERROR) {
		ft_fputstr(str, 2);
		return;
	}
	ft_putstr(str);
}
