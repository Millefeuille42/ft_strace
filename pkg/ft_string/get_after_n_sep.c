//
// Created by millefeuille on 4/24/23.
//

#include "ft_string.h"

char* get_after_last_sep(char* str, const char sep) {
	if (!str)
		return NULL;

	size_t last_sep = 0;
	for (size_t i = 0; str[i]; i++) {
		if (str[i] == sep)
			last_sep = i;
	}

	if (last_sep == 0)
		return str;

	return str + last_sep + 1;
}

char* get_after_n_sep(char* str, const char sep, const size_t n) {
	if (!str)
		return NULL;

	size_t i = 0;
	for (size_t counter = 0; str[i] && counter < n; i++) {
		if (str[i] == sep)
			counter++;
	}

	if (!str[i])
		return str;
	return str + i;
}
