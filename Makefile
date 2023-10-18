COMPILING=Compiling
COMPILING_EXT=Compiling
LINKING=Linking
DELETING=Deleting
DELETING_EXT=Deleting
ON_ERROR=Step returned an error
ON_ERROR_EXT=Step returned an error
BANNER=""
EDITION=""

ifdef MODE
	include ~/make_mode/$(MODE).env
endif

######### Sources #########

SOURCES	=			pkg/ft_print/ft_putnbr_in_between.c \
            		pkg/ft_print/ft_putchar.c \
            		pkg/ft_print/ft_putstr.c \
            		pkg/ft_print/ft_putnbr_base_padded.c \
            		pkg/ft_print/ft_putnbr_base.c \
            		pkg/ft_print/ft_putnbr.c \
					pkg/ft_print/ft_print.c \
            		pkg/ft_log/ft_logstr.c \
            		pkg/ft_log/print_level.c \
            		pkg/ft_log/ft_lognbr_in_between.c \
            		pkg/ft_log/ft_lognbr.c \
            		pkg/ft_error/panic.c \
            		pkg/ft_error/log_error.c \
            		pkg/ft_string/ft_string_copy.c \
            		pkg/ft_string/ft_string_concat.c \
            		pkg/ft_string/get_after_n_sep.c \
            		pkg/ft_string/ft_strcmp.c \
            		pkg/ft_string/ft_to_lower.c \
            		pkg/ft_string/ft_strlen.c \
            		pkg/ft_string/ft_is_alnum.c \
            		pkg/ft_string/ft_split.c \
            		pkg/ft_string/ft_is_alpha.c \
            		pkg/ft_string/string.c \
            		pkg/ft_list/delete_list.c \
            		pkg/ft_list/list_accessors.c \
            		pkg/ft_list/iter_list.c \
            		pkg/ft_list/list_sort.c \
            		pkg/ft_list/ft_list.c \
            		pkg/ft_memory/zeroed_malloc.c \
            		pkg/ft_memory/ft_bzero.c \
            		pkg/ft_memory/del_array.c \
            		pkg/ft_memory/safe_free.c \
            		cmd/ft_strace.c \
					cmd/trace_loop.c\
					cmd/utils.c\
					cmd/trace_print.c\
            		cmd/parsing.c \
            		cmd/syscalls.c \

HEADERS	=	pkg/ft_print/ft_print.h \
            pkg/ft_log/ft_log.h \
            pkg/ft_error/ft_error.h \
            pkg/ft_list/ft_list.h \
            pkg/ft_memory/ft_memory.h \
            pkg/ft_string/ft_string.h \
			cmd/ft_strace.h\
			cmd/syscalls.h\

HEADERS_DIRECTORIES	=	pkg/ft_print/ \
                        pkg/ft_log/ \
                        pkg/ft_error/ \
                        pkg/ft_list/ \
                        pkg/ft_memory/ \
                        pkg/ft_string/ \
                        cmd/ \

INCLUDES =	$(addprefix -I, $(HEADERS_DIRECTORIES))

######### Details #########

NAME	=	ft_strace
SOURCES_EXTENSION = c

######### Compilation #########

COMPILE		=	clang
DELETE		=	rm -f

DEFINES = -DPROGRAM_NAME=\"$(NAME)\"


FLAGS		= -Wall -Werror -Wextra -pedantic $(INCLUDES) $(DEFINES)
LINK_FLAGS  =

######### Additional Paths #########

vpath	%.h $(HEADERS_DIRECTORIES)

ifdef LOG_LEVEL
        DEFINES +=  -DLOG_LEVEL=$(LOG_LEVEL)
else
        DEFINES +=  -DLOG_LEVEL=INFO
endif

# ################################### #
#        DO NOT ALTER FURTHER!        #
# ################################### #

######### Additional Paths #########

vpath	%.o $(OBJS_DIR)
vpath	%.d $(DEPS_DIR)

######### Implicit Macros #########

OBJS_DIR	= .objs/
DEPS_DIR	= .deps/

OBJS	=	$(addprefix $(OBJS_DIR), $(SOURCES:.$(SOURCES_EXTENSION)=.o))
DEPS	=	$(addprefix $(DEPS_DIR), $(SOURCES:.$(SOURCES_EXTENSION)=.d))

#########  Rules  #########

.DEFAULT_GOAL := $(NAME)

all:	$(OBJS_DIR) $(DEPS_DIR) $(NAME) ## Compile project and dependencies

$(NAME):  $(OBJS) ## Compile project
			@printf "$(LINKING) %s\n" $@
			@$(COMPILE) $(FLAGS) $^ $(LINK_FLAGS) -o $@

clean: clean_deps clean_objs ## Delete object files

fclean:	clean clean_bin ## Delete object files and binary

re:	fclean ## Delete object files and binary, then recompile all
			@make --no-print-directory all
help: ## Print this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

#########  Sub Rules  #########

objs:	$(OBJS_DIR) $(DEPS_DIR) $(OBJS)

clean_deps:
		@printf "$(DELETING) %s\n" $(DEPS_DIR)
		@$(DELETE) -r $(DEPS_DIR)
clean_objs:
		@printf "$(DELETING) %s\n" $(OBJS_DIR)
		@$(DELETE) -r $(OBJS_DIR)
clean_bin:
		@printf "$(DELETING) %s\n" $(NAME)
		@$(DELETE) $(NAME)

#########  Implicit Rules  #########

$(OBJS_DIR):
					@mkdir -p $(OBJS_DIR)

$(DEPS_DIR):
					@mkdir -p $(DEPS_DIR)

$(OBJS_DIR)%.o:	%.$(SOURCES_EXTENSION)
			@mkdir -p $(OBJS_DIR)$(dir $<)
			@mkdir -p $(DEPS_DIR)$(dir $<)
			@printf "$(COMPILING) %s\n" $^
			@$(COMPILE) $(FLAGS) -MMD -MP -MF $(DEPS_DIR)$*.d -c $< -o $@

.PHONY:	all clean fclean re help objs clean_bin clean_deps clean_objs

#########  Includes  #########

-include $(DEPS)
