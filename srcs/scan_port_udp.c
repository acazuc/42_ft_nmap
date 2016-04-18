#include "ft_nmap.h"

void scan_port_udp(t_thread_arg *thread_arg, struct iphdr *ip_header, int port)
{
  t_icmp_packet recv_packet;
  t_udp_packet packet;
  size_t started;
  int received;

  packet.ip_header = *ip_header;
  forge_udphdr(&packet, port);
  if (sendto(thread_arg->host->socket_udp, &packet, sizeof(packet), 0, thread_arg->host->addr_udp, thread_arg->host->addrlen_udp) == -1)
  {
    ft_putendl_fd("ft_nmap: failed to send packet", 2);
    exit(EXIT_FAILURE);
  }
  started = epoch_micro();
  received = 0;
  do {
    if (epoch_micro() - started > 1000000)
      break;
    if (recvfrom(thread_arg->host->socket_icmp, &recv_packet, sizeof(recv_packet), 0, thread_arg->host->addr_icmp, (socklen_t*)(&thread_arg->host->addrlen_icmp)) == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        received = 0;
        continue;
      }
      ft_putendl_fd("ft_nmap: failed to receive packet", 2);
      exit(EXIT_FAILURE);
    }
    if (scan_port_udp_finished(&recv_packet))
    {
      received = 1;
      break;
    }
  } while (1);
  if (received)
    thread_arg->host->results[port].status_udp = CLOSED;
  else
    thread_arg->host->results[port].status_udp = OPEN_FILTERED;
}
