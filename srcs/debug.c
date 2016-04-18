#include "ft_nmap.h"

void debug_tcp_packet(t_tcp_packet *packet)
{
  struct iphdr *hdr;
  struct tcphdr *hd;

  hdr = &packet->ip_header;
  printf("version: %d, ihl: %d, tos: %d, tot_len: %d, id: %d, frag_off: %d, ttl: %d, protocol: %d, daddr: %d, saddr: %d, check: %d\n", hdr->version, hdr->ihl, hdr->tos, hdr->tot_len, hdr->id, hdr->frag_off, hdr->ttl, hdr->protocol, hdr->daddr, hdr->saddr, hdr->check);
  fflush(stdout);
  hd = &packet->tcp_header;
  printf("source: %d, dest: %d, seq: %d, ack_seq: %d, doff: %d, fin: %d, syn: %d, rst: %d, psh: %d, ack: %d, urg: %d\n", ntohs(hd->source), ntohs(hd->dest), hd->seq, hd->ack_seq, hd->doff, hd->fin, hd->syn, hd->rst, hd->psh, hd->ack, hd->urg);
  fflush(stdout);
}
