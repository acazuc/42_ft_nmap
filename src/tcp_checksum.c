#include "ft_nmap.h"

int16_t tcp_checksum(t_tcp_packet *packet, int pton_addr)
{
	char *result;
	struct tcp_psdhdr pseudo_hdr;
	int16_t checksum;
	int16_t len;

	len = sizeof(t_tcp_packet) - sizeof(struct iphdr);
	ft_bzero(&pseudo_hdr, sizeof(pseudo_hdr));
	pseudo_hdr.source = pton_addr;
	pseudo_hdr.dest = packet->ip_header.daddr;
	pseudo_hdr.blank = 0;
	pseudo_hdr.protocol = packet->ip_header.protocol;
	pseudo_hdr.len = htons(len);
	if (!(result = malloc(len + sizeof(pseudo_hdr))))
	{
		ft_putendl_fd("ft_nmap: can't build tcp checksum", 2);
		exit(EXIT_FAILURE);
	}
	ft_memcpy(result, &pseudo_hdr, sizeof(pseudo_hdr));
	ft_memcpy(result + sizeof(pseudo_hdr), &packet->tcp_header, len);
	checksum = ip_checksum(result, len + sizeof(pseudo_hdr));
	free(result);
	return (checksum);
}
