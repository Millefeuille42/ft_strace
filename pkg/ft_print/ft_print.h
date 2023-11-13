//
// Created by millefeuille on 4/21/23.
//

#ifndef FT_PRINT_H
# define FT_PRINT_H

# include <unistd.h>
# include <ft_memory.h>

# ifndef FT_PRINT_BUFFER_SIZE
#  define FT_PRINT_BUFFER_SIZE 1024
# endif

# ifndef FT_PRINT_FLUSH_NEWLINE
#  define FT_PRINT_FLUSH_NEWLINE 1
# endif

void ft_putstr(const char *str);
void ft_fputstr(const char *str, int fd);

void ft_putchar(char c);
void ft_fputchar(char c, int fd);

void ft_putnbr(long n);
void ft_fputnbr(long n, int fd);

void ft_putnbr_base(unsigned long nb, const char *base, size_t base_size);
void ft_putnbr_base_padded(unsigned long nb, const char *base, size_t base_size, char pad_c, ssize_t pad_n);
void ft_putnbr_in_between(const char *prefix, long n, const char *suffix);

ssize_t buffered_write(int fd, const char *s, size_t len);
ssize_t flush(int fd);
size_t *get_cursor(int fd);
char *get_buffer(int fd);

#endif //FT_PRINT_H
