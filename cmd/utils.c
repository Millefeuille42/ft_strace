//
// Created by millefeuille on 10/17/23.
//

#include "ft_strace.h"

int find_least_significant_bit_position(int value) {
	if (value == 0) return 0;

	int position = 0;
	for (; !(value & 1); position++) value >>= 1;
	return position;
}

void ft_putstr_escape(const char *str, const size_t read_size) {
	if (!str)
		return;
	for (size_t len = 0; str[len] && (read_size == 0 || len != read_size); len++) {
		if (str[len] == '\n') {
			ft_putstr("\\n");
			continue;
		}
		ft_putchar(str[len]);
	}
}
