#include "ft_nmap.h"

void scan_port_tcp(t_thread_arg *thread_arg, struct iphdr *ip_header, void (*forge_tcphdr)(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr), int port, char *type)
{
	t_tcp_packet *recv_packet;
	t_tcp_packet packet;
	int received;
	uint32_t sequence;
	int retry;
	struct pollfd fds;

	packet.ip_header = *ip_header;
	forge_tcphdr(thread_arg->env, &packet, port, get_send_ip(thread_arg));
	sequence = packet.tcp_header.seq;
	packet_flush_tcp(thread_arg->host, port);
	received = 0;
	retry = 0;
	while (retry < 3 && !received)
	{
		if (sendto(thread_arg->host->socket_tcp, &packet, sizeof(packet), 0, thread_arg->host->addr, thread_arg->host->addrlen) == -1)
		{
			fprintf(stderr, "ft_nmap: failed to send packet\n");
			exit(EXIT_FAILURE);
		}
		int looper = 0;
		while (looper < 10)
		{
			if ((recv_packet = packet_get_tcp(thread_arg->host, port, sequence, type)))
			{
				received = 1;
				break;
			}
			fds.fd = 0;
			fds.events = POLLIN;
			fds.revents = 0;
			if (poll(&fds, 0, 100) == -1)
			{
				fprintf(stderr, "ft_nmap: poll failed");
				exit(EXIT_FAILURE);
			}
			looper++;
		}
		retry++;
	}
	scan_port_tcp_set_result(&thread_arg->host->results[port], type, recv_packet, received);
	packet_flush_tcp(thread_arg->host, port);
}
