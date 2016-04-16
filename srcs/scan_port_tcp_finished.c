#include "ft_nmap.h"

int scan_port_tcp_finished(t_tcp_packet *packet, char *type)
{
  if (!ft_strcmp(type, "SYN"))
  {
    if (packet->tcp_header.syn && packet->tcp_header.ack)
      return (1);
    if (packet->tcp_header.rst && packet->tcp_header.ack)
      return (1);
    return (0);
  }
  if (!ft_strcmp(type, "FIN"))
  {
    if (packet->tcp_header.rst && packet->tcp_header.ack)
      return (1);
    return (0);
  }
  if (!ft_strcmp(type, "XMAS"))
  {
    if (packet->tcp_header.rst && packet->tcp_header.ack)
      return (1);
    return (0);
  }
  if (!ft_strcmp(type, "NULL"))
  {
    if (packet->tcp_header.rst && packet->tcp_header.ack)
      return (1);
    return (0);
  }
  if (!ft_strcmp(type, "ACK"))
  {
    if (packet->tcp_header.rst)
      return (1);
    return (0);
  }
  return (0);
}
