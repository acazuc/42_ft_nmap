#include "ft_nmap.h"

int scan_port_udp_finished(t_icmp_packet *packet)
{
  if (packet->icmp_header.type == 3 && packet->icmp_header.code == 3)
    return (1);
  return (0);
}
