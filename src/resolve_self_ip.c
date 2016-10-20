/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve_self_ip.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: acazuc <acazuc@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/15 16:35:09 by acazuc            #+#    #+#             */
/*   Updated: 2016/10/20 20:28:44 by acazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	resolve_self_ip(t_env *env)
{
	struct ifaddrs *origin;
	struct ifaddrs *lst;
	char ipset = 0;

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
			ipset |= 1;
			env->loopback_ip = ((struct sockaddr_in*)lst->ifa_addr)->sin_addr.s_addr;
		}
		else if (ipset & 2)
		{
			ft_putendl_fd("ft_nmap: ip network collision; passing", 2);
		}
		else
		{
			ipset |= 2;
			env->local_ip = ((struct sockaddr_in*)lst->ifa_addr)->sin_addr.s_addr;
		}
		lst = lst->ifa_next;
	}
	if (origin)
		freeifaddrs(origin);
	if (ipset == 3)
		return;
	ft_putendl_fd("ft_nmap: can't resolve external ip", 2);
	exit(EXIT_FAILURE);
}
