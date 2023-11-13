//
// Created by millefeuille on 10/18/23.
//

#include "ft_print.h"

size_t* get_cursor(const int fd) {
	static size_t cursor[2] = {0};
	return fd != 1 && fd != 2 ? NULL : &cursor[fd - 1];
}

char* get_buffer(const int fd) {
	static char buffer[2][FT_PRINT_BUFFER_SIZE] = {0};
	return fd != 1 && fd != 2 ? NULL : buffer[fd - 1];
}

ssize_t flush(const int fd) {
	char* buffer = get_buffer(fd);
	if (!buffer) return 0;
	size_t* len = get_cursor(fd);
	if (!len) return 0;

	//write(1, "\n\nFLUSHING\n\n", sizeof("\n\nFLUSHING\n"));
	const ssize_t ret = write(fd, buffer, *len);
	ft_bzero(buffer, FT_PRINT_BUFFER_SIZE);
	*len = 0;
	return ret;
}

ssize_t buffered_write(const int fd, const char* s, const size_t len) {
	char* buffer = get_buffer(fd);
	size_t* cursor = get_cursor(fd);
	if (!buffer | !len) return write(fd, s, len);

	size_t count = 0;
	for (; count < len; count++) {
		buffer[*cursor] = s[count];
		*cursor += 1;
		if ((FT_PRINT_FLUSH_NEWLINE && s[count] == '\n') || *cursor == FT_PRINT_BUFFER_SIZE) {
			flush(fd);
		}
	}

	return (ssize_t)count;
}

__attribute__((destructor))
void final_flush(void) {
	flush(1);
	flush(2);
}
