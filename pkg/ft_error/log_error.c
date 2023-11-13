//
// Created by millefeuille on 4/21/23.
//

#include "ft_error.h"

void log_error(const char* add) {
	ft_logstr(ERROR, PROGRAM_NAME);
	ft_logstr_no_header(ERROR, ": error: ");
	ft_logstr_no_header(ERROR, add);
	ft_logstr_no_header(ERROR, "\n");
}
