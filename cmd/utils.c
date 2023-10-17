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

void ft_putstr_escape(char *str, size_t read_size) {
	if (!str)
		return;
	size_t len = 0;
	for (; str[len] && len != read_size; len++) {
		if (str[len] == '\n') {
			write(1, "\\n", 2);
			continue;
		}
		write(1, &str[len], 1);
	}
}
