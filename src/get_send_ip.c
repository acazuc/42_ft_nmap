/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_send_ip.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: acazuc <acazuc@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/17 18:41:30 by acazuc            #+#    #+#             */
/*   Updated: 2016/10/17 18:50:45 by acazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int get_send_ip(t_thread_arg *arg)
{
	int ip = ((struct sockaddr_in*)arg->host->addr)->sin_addr.s_addr;
	if ((ip & 0xff) == 0x7f)
	{
		ft_putendl("yeah");
		return (htonl(2130706433));
	}
	else if (ip == 0)
	{
		ft_putendl("yeah2");
		return (htonl(2130706433));
	}
	return (arg->env->local_ip);
}
