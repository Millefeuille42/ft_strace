//
// Created by millefeuille on 9/19/23.
//

#include "ft_print.h"

void ft_putnbr_in_between(const char *prefix, const long n, const char *suffix) {
	ft_putstr(prefix);
	ft_putnbr(n);
	ft_putstr(suffix);
}
