# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: acazuc <acazuc@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2015/11/25 06:50:12 by acazuc            #+#    #+#              #
#    Updated: 2016/10/15 16:42:37 by acazuc           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_nmap

CC = gcc

CFLAGS = -Wall -Wextra -Werror -Ofast

INCLUDES_PATH = include/

SRCS_PATH = src/

SRCS_NAME = main.c \
			env_default.c \
			env_init.c \
			file_get_contents.c \
			parse_file.c \
			parse_ip.c \
			parse_params.c \
			parse_ports.c \
			parse_scan.c \
			parse_speedup.c \
			print_help.c \
			valid_port.c \
			env_check_port_number.c \
			get_ports_number.c \
			scan_host.c \
			print_debug.c \
			build_hosts.c \
			push_host.c \
			ip_checksum.c \
			forge_iphdr.c \
			forge_tcphdr.c \
			forge_udphdr.c \
			thread_run.c \
			scan_port.c \
			tcp_checksum.c \
			scan_port_tcp.c \
			scan_port_tcp_finished.c \
			scan_port_tcp_set_result.c \
			epoch_micro.c \
			print_result.c \
			get_scan_result_str.c \
			get_scan_conclusion.c \
			port_status_opened.c \
			get_scan_type_number.c \
			get_service_name.c \
			debug.c \
			udp_checksum.c \
			scan_port_udp.c \
			packet_flush.c \
			packet_get.c \
			port_listener.c \
			packet_push.c \
			resolve_self_ip.c \

SRCS = $(addprefix $(SRCS_PATH), $(SRCS_NAME))

OBJS_PATH = obj/

OBJS_NAME = $(SRCS_NAME:.c=.o)

OBJS = $(addprefix $(OBJS_PATH), $(OBJS_NAME))

LIBRARY = -L libft -lft -lpthread

all: odir $(NAME)

$(NAME): $(OBJS)
	@make -C libft
	@echo " - Making $(NAME)"
	@$(CC) $(CFLAGS) -o $(NAME) $^ $(LIBRARY)

$(OBJS_PATH)%.o: $(SRCS_PATH)%.c
	@echo " - Compiling $<"
	@$(CC) $(CFLAGS) -o $@ -c $< -I$(INCLUDES_PATH)

odir:
	@mkdir -p $(OBJS_PATH)

clean:
	@make -C libft clean
	@echo " - Cleaning objs"
	@rm -f $(OBJS)

fclean: clean
	@make -C libft fclean
	@echo " - Cleaning executable"
	@rm -f $(NAME)

re: fclean all

.PHONY: clean fclean re odir
