//
// Created by millefeuille on 4/21/23.
//

#include "ft_print.h"

void ft_putchar(const char c) {
	buffered_write(1, &c, 1);
}

void ft_fputchar(const char c, const int fd) {
	if (fd < 0)
		return;
	buffered_write(fd, &c, 1);
}
