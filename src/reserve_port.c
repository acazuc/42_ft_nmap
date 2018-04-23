/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   reserve_port.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: acazuc <acazuc@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/16 11:37:12 by acazuc            #+#    #+#             */
/*   Updated: 2018/04/23 18:26:51 by acazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void reserve_port(t_env *env)
{
	struct sockaddr_in sa;
	int sockfd;
	unsigned short i;
	unsigned int tmp;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, RED "ft_nmap: socket() failed\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	i = 0;
	while (i < 500)
	{
		tmp = 49152 + lcrandom() % (65535 - 49152);
		sa.sin_port = htons(tmp);
		if (bind(sockfd, (struct sockaddr*)&sa, sizeof(sa)) == 0)
		{
			env->port = tmp;
			return;
		}
		++i;
	}
	fprintf(stderr, RED "ft_nmap: can't bind port\n" DEFAULT);
	exit(EXIT_FAILURE);
}
