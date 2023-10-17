//
// Created by millefeuille on 4/24/23.
//

#include "ft_strace.h"

strace_args parse_args(int argc, char **argv) {
	ft_list *files = NULL;
	strace_args ret = (strace_args){.files = NULL, .flags = '\0', .err = -1};

	for (int i = 1; i < argc; i++) {
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
	return ret;
}
