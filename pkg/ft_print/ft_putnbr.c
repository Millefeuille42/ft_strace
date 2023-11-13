//
// Created by millefeuille on 4/21/23.
//

#include "ft_print.h"

void ft_fputnbr(const long n, const int fd) {
	long int nb = n;
	if (nb < 0) {
		nb = -nb;
		buffered_write(1, "-", 1);
	}
	if (nb > 9) {
		ft_fputnbr(nb / 10, fd);
		nb = nb % 10;
	}
	nb = nb + 48;
	buffered_write(fd, (const char *)&nb, 1);
}

void ft_putnbr(const long n) {
	long int nb = n;
	if (nb < 0) {
		nb = -nb;
		buffered_write(1, "-", 1);
	}
	if (nb > 9) {
		ft_putnbr(nb / 10);
		nb = nb % 10;
	}
	nb = nb + 48;
	buffered_write(1, (const char *)&nb, 1);
}
