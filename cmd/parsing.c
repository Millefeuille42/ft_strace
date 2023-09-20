//
// Created by millefeuille on 4/24/23.
//

#include "ft_strace.h"

static void print_help(void) {
	ft_putstr("Usage: ft_strace [option(s)] [file(s)]\n");
}

static char parse_flags(char flags, char *str) {
	for (int i = 1; str[i]; i++) {
		switch (str[i]) {
			case 'h':
				print_help();
				return -2;
			default:
				if (str[i]) {
					print_help();
					ft_putchar('\n');
					ft_putstr("Invalid flag: ");
					ft_putchar(str[i]);
					ft_putchar('\n');
					return -1;
				}
				break;
		}
	}
	return flags;
}

strace_args parse_args(int argc, char **argv) {
	ft_list *files = NULL;
	strace_args ret = (strace_args){.files = NULL, .flags = '\0', .err = -1};

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && ft_strlen(argv[i]) > 1) {
			ret.flags = parse_flags(ret.flags, argv[i]);
			if (ret.flags < 0) {
				ret.err = -2;
				delete_list_forward(&files, safe_free);
				return ret;
			}
			continue;
		}
		char *arg = ft_string(argv[i]);
		if (!arg) {
			delete_list_forward(&files, safe_free);
			return ret;
		}
		ft_list *new_element = new_element_to_list(files, arg);
		if (!new_element) {
			safe_free((void **) &arg);
			delete_list_forward(&files, safe_free);
			return ret;
		}
		if (!files)
			files = new_element;
	}

	ret.files = files;
	ret.err = 0;
	if (ret.files && ret.files->next)
		STRACE_SET_FLAG(ret.flags, STRACE_FLAG_dirs);
	return ret;
}
