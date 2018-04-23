#include "ft_nmap.h"

static void forge_tcphdr_common(t_env *env, struct tcphdr *header, int16_t port)
{
	ft_memset(header, 0, sizeof(*header));
	header->source = htons(env->port);
	header->dest = htons(port);
	header->seq = lcrandom();
	header->ack_seq = 0;
	header->doff = 5;
	header->fin = 0;
	header->syn = 0;
	header->rst = 0;
	header->psh = 0;
	header->ack = 0;
	header->urg = 0;
	header->window = htons(1024);
	header->check = 0;
	header->urg_ptr = 0;
}

void forge_tcphdr_syn(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr)
{
	forge_tcphdr_common(env, &packet->tcp_header, port);
	packet->tcp_header.syn = 1;
	packet->tcp_header.check = tcp_checksum(packet, pton_addr);
}

void forge_tcphdr_null(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr)
{
	forge_tcphdr_common(env, &packet->tcp_header, port);
	packet->tcp_header.check = tcp_checksum(packet, pton_addr);
}

void forge_tcphdr_ack(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr)
{
	forge_tcphdr_common(env, &packet->tcp_header, port);
	packet->tcp_header.ack = 1;
	packet->tcp_header.check = tcp_checksum(packet, pton_addr);
}

void forge_tcphdr_fin(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr)
{
	forge_tcphdr_common(env, &packet->tcp_header, port);
	packet->tcp_header.fin = 1;
	packet->tcp_header.check = tcp_checksum(packet, pton_addr);
}

void forge_tcphdr_xmas(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr)
{
	forge_tcphdr_common(env, &packet->tcp_header, port);
	packet->tcp_header.fin = 1;
	packet->tcp_header.psh = 1;
	packet->tcp_header.urg = 1;
	packet->tcp_header.check = tcp_checksum(packet, pton_addr);
}
