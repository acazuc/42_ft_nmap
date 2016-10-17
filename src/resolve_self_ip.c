/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve_self_ip.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: acazuc <acazuc@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/15 16:35:09 by acazuc            #+#    #+#             */
/*   Updated: 2016/10/17 18:29:46 by acazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	resolve_self_ip(t_env *env)
{
	struct ifaddrs *origin;
	struct ifaddrs *lst;

	getifaddrs(&origin);
	lst = origin;
	while (lst)
	{
		if (!lst->ifa_addr)
		{
			lst = lst->ifa_next;
			continue;
		}
		if (lst->ifa_addr->sa_family != AF_INET)
		{
			lst = lst->ifa_next;
			continue;
		}
		if (!ft_strcmp(lst->ifa_name, "lo"))
		{
			lst = lst->ifa_next;
			continue;
		}
		env->local_ip = ((struct sockaddr_in*)lst->ifa_addr)->sin_addr.s_addr;
		if (lst->ifa_netmask)
		{
			ft_putendl(inet_ntoa(((struct sockaddr_in*)lst->ifa_netmask)->sin_addr));
		}
		freeifaddrs(origin);
		return;
	}
	if (origin)
		freeifaddrs(origin);
	ft_putendl_fd("nmap: can't resolve external ip", 2);
	exit(EXIT_FAILURE);
}
