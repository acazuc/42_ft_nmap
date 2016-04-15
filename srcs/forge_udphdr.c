#include "ft_nmap.h"

void forge_udphdr(struct udphdr *header, int16_t port)
{
  ft_bzero(header, sizeof(*header));
  header->source = htons(1234);
  header->dest = htons(port);
  header->len = htons(sizeof(t_udp_packet) - sizeof(*header));
  header->check = ip_checksum(header, sizeof(t_udp_packet) - sizeof(*header));
}
