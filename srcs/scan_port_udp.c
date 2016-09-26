#include "ft_nmap.h"

void scan_port_udp(t_thread_arg *thread_arg, struct iphdr *ip_header, int port)
{
	t_udp_packet packet;
	size_t started;
	int received;

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
		if (epoch_micro() - started > 1000000)
			break;
		if (packet_get_icmp(thread_arg->host, port))
		{
			received = 1;
			break;
		}
	}
	packet_flush_icmp(thread_arg->host, port);
	if (received)
		thread_arg->host->results[port].status_udp = CLOSED;
	else
		thread_arg->host->results[port].status_udp = OPEN_FILTERED;
}
