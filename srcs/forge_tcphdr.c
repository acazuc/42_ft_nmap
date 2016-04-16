#include "ft_nmap.h"

static void forge_tcphdr_common(struct tcphdr *header, int16_t port)
{
  ft_bzero(header, sizeof(*header));
  header->source = htons(1234);
  header->dest = htons(port);
  header->seq = 0;
  header->ack_seq = 0;
  header->doff = 5;
  header->fin = 0;
  header->syn = 0;
  header->rst = 0;
  header->psh = 0;
  header->ack = 0;
  header->urg = 0;
  header->window = htons(6000);
  header->check = 0;
  header->urg_ptr = 0;
}

void forge_tcphdr_syn(t_tcp_packet *packet, struct tcphdr *header, int16_t port)
{
  forge_tcphdr_common(header, port);
  header->syn = 1;
  header->check = tcp_checksum(packet);
}

void forge_tcphdr_null(t_tcp_packet *packet, struct tcphdr *header, int16_t port)
{
  forge_tcphdr_common(header, port);
  header->check = tcp_checksum(packet);
}

void forge_tcphdr_ack(t_tcp_packet *packet, struct tcphdr *header, int16_t port)
{
  forge_tcphdr_common(header, port);
  header->ack = 1;
  header->check = tcp_checksum(packet);
}

void forge_tcphdr_fin(t_tcp_packet *packet, struct tcphdr *header, int16_t port)
{
  forge_tcphdr_common(header, port);
  header->fin = 1;
  header->check = tcp_checksum(packet);
}

void forge_tcphdr_xmas(t_tcp_packet *packet, struct tcphdr *header, int16_t port)
{
  forge_tcphdr_common(header, port);
  header->fin = 1;
  header->psh = 1;
  header->urg = 1;
  header->check = tcp_checksum(packet);
}
