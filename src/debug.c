#include "ft_nmap.h"

static void debug_ip_header(struct iphdr *hdr)
{
	printf("version: %d, ihl: %d, tos: %d, tot_len: %d, id: %d, frag_off: %d, ttl: %d, protocol: %d, daddr: %d, saddr: %d, check: %d\n", hdr->version, hdr->ihl, hdr->tos, hdr->tot_len, hdr->id, hdr->frag_off, hdr->ttl, hdr->protocol, hdr->daddr, hdr->saddr, hdr->check);
}

void debug_tcp_packet(t_tcp_packet *packet)
{
	struct tcphdr *hd;

	debug_ip_header(&packet->ip_header);
	hd = &packet->tcp_header;
	printf("source: %d, dest: %d, seq: %d, ack_seq: %d, doff: %d, fin: %d, syn: %d, rst: %d, psh: %d, ack: %d, urg: %d\n", ntohs(hd->source), ntohs(hd->dest), hd->seq, hd->ack_seq, hd->doff, hd->fin, hd->syn, hd->rst, hd->psh, hd->ack, hd->urg);
}

void debug_udp_packet(t_udp_packet *packet)
{
	struct udphdr *hd;

	debug_ip_header(&packet->ip_header);
	hd = &packet->udp_header;
	printf("source: %d, dest: %d, len: %d, check: %d\n", ntohs(hd->source), ntohs(hd->dest), hd->len, hd->check);
}

void debug_icmp_packet(t_icmp_packet *packet)
{
	struct icmphdr *hd;

	debug_ip_header(&packet->ip_header);
	hd = &packet->icmp_header;
	printf("type: %d, code: %d, check: %d\n", hd->type, hd->code, hd->checksum);
}
