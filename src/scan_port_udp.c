#include "ft_nmap.h"

void scan_port_udp(t_thread_arg *thread_arg, struct iphdr *ip_header, int port)
{
	t_udp_packet packet;
	size_t started;
	int received;
	struct pollfd fds;
	int tries;

	tries = 0;
	while (tries < 3 && !received)
	{
		packet.ip_header = *ip_header;
		forge_udphdr(&packet, port);
		packet_flush_icmp(thread_arg->host, port);
		if (sendto(thread_arg->host->socket_udp, &packet, sizeof(packet), 0, thread_arg->host->addr, thread_arg->host->addrlen) == -1)
		{
			ft_putendl_fd("ft_nmap: failed to send packet", 2);
			exit(EXIT_FAILURE);
		}
		started = epoch_micro();
		received = 0;
		while (1)
		{
			int timer = 1000000 - (epoch_micro() - started);
			if (timer < 0)
				break;
			fds.fd = 0;
			fds.events = POLLIN;
			fds.revents = 0;
			if (poll(&fds, 0, timer / 1000) == -1)
			{
				ft_putendl_fd("ft_nmap: poll failed", 2);
				exit(EXIT_FAILURE);
			}
			if (packet_get_icmp(thread_arg->host, port))
			{
				received = 1;
				break;
			}
		}
		tries++;
	}
	packet_flush_icmp(thread_arg->host, port);
	if (received)
		thread_arg->host->results[port].status_udp = CLOSED;
	else
		thread_arg->host->results[port].status_udp = OPEN_FILTERED;
}
