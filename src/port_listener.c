#include "ft_nmap.h"

static int listen_tcp(t_host *host, t_tcp_packet *packet)
{
	if (recvfrom(host->socket_tcp, packet, sizeof(*packet), 0, host->addr, (socklen_t*)(&host->addrlen)) == -1)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (0);
		ft_putendl_fd("ft_nmap: failed to receive packet", 2);
		exit(EXIT_FAILURE);
	}
	return (1);
}

static int listen_icmp(t_host *host, t_icmp_packet *packet)
{
	if (recvfrom(host->socket_icmp, packet, sizeof(*packet), 0, host->addr, (socklen_t*)(&host->addrlen)) == -1)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (0);
		ft_putendl_fd("ft_nmap: failed to receive packet", 2);
		exit(EXIT_FAILURE);
	}
	return (1);
}

static t_tcp_packet *packet_tcp_alloc(void)
{
	t_tcp_packet *packet;

	if (!(packet = malloc(sizeof(*packet))))
	{
		ft_putendl_fd("ft_nmap: can't malloc packet", 2);
		exit(EXIT_FAILURE);
	}
	return (packet);
}

static t_icmp_packet *packet_icmp_alloc(void)
{
	t_icmp_packet *packet;

	if (!(packet = malloc(sizeof(*packet))))
	{
		ft_putendl_fd("ft_nmap: can't malloc packet", 2);
		exit(EXIT_FAILURE);
	}
	return (packet);
}

void sigalrm_listen(int sig)
{
	(void)sig;
	ft_putendl("YEAH");
}

void *port_listener(void *data)
{
	t_tcp_packet *packet_tcp;
	t_icmp_packet *packet_icmp;
	t_thread_arg *arg;
	struct pollfd fds[2];

	signal(SIGALRM, sigalrm_listen);
	arg = (t_thread_arg*)data;
	packet_tcp = packet_tcp_alloc();
	packet_icmp = packet_icmp_alloc();
	while (!arg->host->ended)
	{
		fds[0].fd = arg->host->socket_tcp;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = arg->host->socket_icmp;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		if (poll(fds, 2, 1000) == -1)
		{
			ft_putendl_fd("ft_nmap: poll failed", 2);
			exit(EXIT_FAILURE);
		}
		if (arg->env->type_syn || arg->env->type_null || arg->env->type_ack
				|| arg->env->type_fin || arg->env->type_xmas)
		{
			if (listen_tcp(arg->host, packet_tcp))
			{
				if (packet_tcp->tcp_header.dest == htons(arg->env->port))
				{
					packet_push_tcp(arg->host, packet_tcp);
					packet_tcp = packet_tcp_alloc();
				}
			}
		}
		if (arg->env->type_udp)
		{
			if (listen_icmp(arg->host, packet_icmp))
			{
				packet_push_icmp(arg->host, packet_icmp);
				packet_icmp = packet_icmp_alloc();
			}
		}
	}
	return (NULL);
}
