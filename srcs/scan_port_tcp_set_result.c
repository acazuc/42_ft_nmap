#include "ft_nmap.h"

void scan_port_tcp_set_result(t_port_result *result, char *type, t_tcp_packet *packet, int received)
{
  if (!ft_strcmp(type, "SYN"))
  {
    if (!received)
      result->status_syn = FILTERED;
    else if (packet->tcp_header.syn && packet->tcp_header.ack)
      result->status_syn = OPEN;
    else
      result->status_syn = CLOSED;
  }
  else if (!ft_strcmp(type, "FIN"))
  {
    if (!received)
      result->status_fin = OPEN_FILTERED;
    else
      result->status_fin = CLOSED;
  }
  else if (!ft_strcmp(type, "XMAS"))
  {
    if (!received)
      result->status_xmas = OPEN_FILTERED;
    else
      result->status_xmas = CLOSED;
  }
  else if (!ft_strcmp(type, "NULL"))
  {
    if (!received)
      result->status_null = OPEN_FILTERED;
    else
      result->status_null = CLOSED;
  }
  else if (!ft_strcmp(type, "ACK"))
  {
    if (!received)
      result->status_ack = FILTERED;
    else
      result->status_ack = UNFILTERED;
  }
}
