//
// Created by millefeuille on 4/28/23.
//

#include "ft_print.h"

static void ft_set(unsigned long nb, const size_t l, const size_t bl, const char* b) {
	char n[l];

	size_t i = l - 1;
	while (nb >= bl) {
		n[i] = b[(nb % bl)];
		nb = nb / bl;
		i--;
	}
	n[0] = b[nb];
	i = 0;
	while (i != l) {
		buffered_write(1, &n[i], 1);
		i++;
	}
}

void ft_putnbr_base(unsigned long nb, const char* base, const size_t base_size) {
	const unsigned long nb2 = nb;
	size_t length = 1;

	while (nb >= base_size) {
		nb = nb / base_size;
		length++;
	}
	ft_set(nb2, length, base_size, base);
}
