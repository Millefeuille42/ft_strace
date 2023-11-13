//
// Created by millefeuille on 6/26/23.
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

static void ft_pad(const size_t len, const size_t pad_len, const char pad_c) {
	for (size_t i = pad_len - len; i > 0; i--)
		buffered_write(1, &pad_c, 1);
}

void ft_putnbr_base_padded(
	unsigned long nb,
	const char* base,
	const size_t
	base_size,
	const char pad_c,
	const ssize_t pad_n
) {
	const unsigned long nb2 = nb;
	size_t length = 1;

	while (nb >= base_size) {
		nb = nb / base_size;
		length++;
	}

	if (pad_n < 0) ft_pad(length, (size_t)(pad_n * -1), pad_c);
	ft_set(nb2, length, base_size, base);
	if (pad_n > 0) ft_pad(length, (size_t)pad_n, pad_c);
}
