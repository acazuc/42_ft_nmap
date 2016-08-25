#include "ft_nmap.h"

void forge_udphdr(t_udp_packet *packet, int16_t port)
{
	ft_bzero(&packet->udp_header, sizeof(packet->udp_header));
	packet->udp_header.source = htons(1234);
	packet->udp_header.dest = htons(port);
	packet->udp_header.len = htons(sizeof(t_udp_packet) - sizeof(packet->udp_header));
	packet->udp_header.check = udp_checksum(packet);
}
