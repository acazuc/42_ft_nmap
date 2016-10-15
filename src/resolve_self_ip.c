/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve_self_ip.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: acazuc <acazuc@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/15 16:35:09 by acazuc            #+#    #+#             */
/*   Updated: 2016/10/15 17:03:55 by acazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void build_ip_header(struct iphdr *header)
{
	ft_bzero(header, sizeof(*header));
	header->version = 4;
	header->ihl = 5;
	header->tos = 0;
	header->tot_len = sizeof(t_ping_packet);
	header->id = ICMP_ECHO;
	header->frag_off = 0;
	header->ttl = 255;
	header->protocol = IPPROTO_ICMP;
	header->check = 0;
	header->daddr = 134744072;
	header->saddr = 0;
	header->check = 0;
}

static void build_icmp_header(struct icmphdr *header)
{
	ft_bzero(header, sizeof(*header));
	header->type = ICMP_ECHO;
	header->code = 0;
	header->un.echo.id = getpid();
	header->un.echo.sequence = 1;
	header->checksum = 0;
	header->checksum = ip_checksum(header, sizeof(t_ping_packet) - sizeof(struct iphdr));
}

void	resolve_self_ip(t_env *env)
{
	t_ping_packet recv_packet;
	t_ping_packet packet;
	struct timeval tv;
	int sock;
	int val;
	int i;

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
	{
		ft_putendl_fd("ft_nmap: socket failed", 2);
		exit(EXIT_FAILURE);
	}
	val = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) == -1)
	{
		ft_putendl_fd("ft_nmap: can't set HDRINCL", 2);
		exit(EXIT_FAILURE);
	}
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		ft_putendl_fd("ft_nmap: can't change socket recvtime", 2);
		exit(EXIT_FAILURE);
	}
	build_ip_header(&packet.ip_header);
	build_icmp_header(&packet.icmp_header);
	ft_bzero(packet.data, sizeof(packet.data));
	while (i < 10) // max 10s (10 * 1s)
	{
		if (sendto(sock, &packet, sizeof(packet), 0, &sa, &sl) == -1)
		{
			ft_putendl_fd("ft_nmap: can't send ping packet", 2);
			exit(EXIT_FAILURE);
		}
		int j = 0;
		while (j < 10) // 1s
		{
			if (recvfrom(sock, &recv_packet, sizeof(recv_packet), 0, &sa, &sl) == -1)
			{
				if (errno != EAGAIN && errno != EWOULDBLOCK)
				{
					ft_putendl_fd("ft_nmap: can't receive ping packet", 2);
					exit(EXIT_FAILURE);
				}
				++j;
				continue;
			}
			if (recv_packet.icmp_header.type == ICMP_ECHO_REPLY
					&& recv_packet.icmp_header.un.echo.id == getpid()
					&& recv_packet.icmp_header.un.echo.sequence == 1)
			{
				env->local_ip = recv_packet.ip_header.daddr;
				close(sock);
				return;
			}
			++j;
		}
		++i;
	}
	ft_putendl_fd("ft_nmap: can't get local ip", 2);
	exit(EXIT_FAILURE);
}
