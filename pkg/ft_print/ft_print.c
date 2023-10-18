//
// Created by millefeuille on 10/18/23.
//

#include "ft_print.h"

inline static ssize_t flush(int fd, char *buffer, size_t *len) {
	ssize_t ret = write(fd, buffer, *len);
	ft_bzero(buffer, FT_PRINT_BUFFER_SIZE);
	*len = 0;
	return ret;
}

ssize_t buffered_write(int fd, const char *s, size_t len) {
	static char buffer[2][FT_PRINT_BUFFER_SIZE] = {0};
	static size_t cursor[2] = {0};
	size_t count = 0;

	if (fd != 1 && fd != 2) return write(fd, s, len);

	int index = fd - 1;
	for (; count < len; count++) {
		buffer[index][cursor[index]] = s[count];
		cursor[index]++;
		if (s[count] == '\n' || cursor[index] == FT_PRINT_BUFFER_SIZE) {
			flush(fd, buffer[index], &cursor[index]);
			continue;
		}
	}

	return (ssize_t)count;
}

__attribute__((destructor))
void final_flush(void) {
	for (size_t i = 0; i < FT_PRINT_BUFFER_SIZE; i++) {
		buffered_write(1, "\0", 1);
		buffered_write(2, "\0", 1);
	}
}
