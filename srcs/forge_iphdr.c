#include "ft_nmap.h"

void forge_iphdr(struct iphdr *header, int protocol, int pton_addr, size_t packlen)
{
  ft_bzero(header, sizeof(*header));
	header->version = 4;
	header->ihl = 5;
	header->tos = 16;
	header->tot_len = packlen;
	header->id = 1;
	header->frag_off = 0;
	header->ttl = 255;
	header->protocol = protocol;
	header->daddr = pton_addr;
	header->saddr = 0;
	header->check = 0;
}
