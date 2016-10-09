#include "ft_nmap.h"

void scan_port_tcp(t_thread_arg *thread_arg, struct iphdr *ip_header, void (*forge_tcphdr)(t_tcp_packet *packet, int16_t port, int pton_addr), int port, char *type)
{
	t_tcp_packet *recv_packet;
	t_tcp_packet packet;
	size_t started;
	int received;
	uint32_t sequence;
	int retry;
	struct pollfd fds;

	packet.ip_header = *ip_header;
	forge_tcphdr(&packet, port, htonl(631258100));
	sequence = packet.tcp_header.seq;
	packet_flush_tcp(thread_arg->host, port);
	received = 0;
	retry = 0;
	while (retry < 2 && !received)
	{
		if (sendto(thread_arg->host->socket_tcp, &packet, sizeof(packet), 0, thread_arg->host->addr, thread_arg->host->addrlen) == -1)
		{
			ft_putendl_fd("ft_nmap: failed to send packet", 2);
			exit(EXIT_FAILURE);
		}
		started = epoch_micro();
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
			ft_putchar('a');
			if ((recv_packet = packet_get_tcp(thread_arg->host, port, sequence, type)))
			{
				received = 1;
				break;
			}
		}
		retry++;
	}
	scan_port_tcp_set_result(&thread_arg->host->results[port], type, recv_packet, received);
	packet_flush_tcp(thread_arg->host, port);
}
