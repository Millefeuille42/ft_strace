cmake_minimum_required(VERSION 3.10)
project(ft_strace C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=c99 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
        -Wold-style-definition -D_POSIX_C_SOURCE=200809Ln")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -std=c99 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
        -Wold-style-definition -D_POSIX_C_SOURCE=200809L")

include_directories(./pkg/ft_error)
include_directories(./pkg/ft_print)
include_directories(./pkg/ft_string)
include_directories(./pkg/ft_memory)
include_directories(./pkg/ft_log)

set(SOURCE_FT_STRACE
        pkg/ft_print/ft_putnbr_in_between.c
        pkg/ft_print/ft_putchar.c
        pkg/ft_print/ft_putstr.c
        pkg/ft_print/ft_putnbr_base_padded.c
        pkg/ft_print/ft_putnbr_base.c
        pkg/ft_print/ft_putnbr.c
        pkg/ft_print/ft_print.h
        pkg/ft_print/ft_print.c

        pkg/ft_log/ft_logstr.c
        pkg/ft_log/print_level.c
        pkg/ft_log/ft_lognbr_in_between.c
        pkg/ft_log/ft_lognbr.c
        pkg/ft_log/ft_log.h

        pkg/ft_error/panic.c
        pkg/ft_error/log_error.c
        pkg/ft_error/ft_error.h

        pkg/ft_string/ft_string_copy.c
        pkg/ft_string/get_after_n_sep.c
        pkg/ft_string/ft_strcmp.c
        pkg/ft_string/ft_strlen.c
        pkg/ft_string/string.c
        pkg/ft_string/ft_string_concat.c
        pkg/ft_string/ft_string.h

        pkg/ft_memory/ft_bzero.c
        pkg/ft_memory/safe_free.c
        pkg/ft_memory/zeroed_malloc.c
        pkg/ft_memory/ft_memory.h

        cmd/ft_strace.c
        cmd/trace_loop.c
        cmd/utils.c
        cmd/trace_print.c
        cmd/signals.c
        cmd/ft_strace.h

        cmd/syscalls.c
        cmd/syscalls.h
        cmd/libtrace.c
        cmd/libtrace.h

)

add_executable(ft_strace ${SOURCE_FT_STRACE})
