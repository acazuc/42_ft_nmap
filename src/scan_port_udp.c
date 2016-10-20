#include "ft_nmap.h"

void scan_port_udp(t_thread_arg *thread_arg, struct iphdr *ip_header, int port)
{
	t_udp_packet packet;
	int received;
	struct pollfd fds;
	int retry;

	packet.ip_header = *ip_header;
	forge_udphdr(thread_arg->env, &packet, port, get_send_ip(thread_arg));
	packet_flush_icmp(thread_arg->host, port);
	received = 0;
	retry = 0;
	while (retry < 3 && !received)
	{
		if (sendto(thread_arg->host->socket_udp, &packet, sizeof(packet), 0, thread_arg->host->addr, thread_arg->host->addrlen) == -1)
		{
			ft_putendl_fd("ft_nmap: failed to send packet", 2);
			exit(EXIT_FAILURE);
		}
		int looper = 0;
		while (looper < 10)
		{
			if (packet_get_icmp(thread_arg->host, port))
			{
				received = 1;
				break;
			}
			fds.fd = 0;
			fds.events = POLLIN;
			fds.revents = 0;
			if (poll(&fds, 0, 100) == -1)
			{
				ft_putendl_fd("ft_nmap: poll failed", 2);
				exit(EXIT_FAILURE);
			}
			looper++;
		}
		retry++;
	}
	packet_flush_icmp(thread_arg->host, port);
	if (received)
		thread_arg->host->results[port].status_udp = CLOSED;
	else
		thread_arg->host->results[port].status_udp = OPEN_FILTERED;
}
