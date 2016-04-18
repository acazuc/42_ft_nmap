#include "ft_nmap.h"

void scan_port_tcp(t_thread_arg *thread_arg, struct iphdr *ip_header, void (*forge_tcphdr)(t_tcp_packet *packet, int16_t port), int port, char *type)
{
  t_tcp_packet packet;
  size_t started;
  int received;

  packet.ip_header = *ip_header;
  forge_tcphdr(&packet, port);
  if (sendto(thread_arg->host->socket_tcp, &packet, sizeof(packet), 0, thread_arg->host->addr_tcp, thread_arg->host->addrlen_tcp) == -1)
  {
    ft_putendl_fd("ft_nmap: failed to send packet", 2);
    exit(EXIT_FAILURE);
  }
  started = epoch_micro();
  received = 0;
  do {
    if (epoch_micro() - started > 1000000)
      break;
    if (recvfrom(thread_arg->host->socket_tcp, &packet, sizeof(packet), 0, thread_arg->host->addr_tcp, (socklen_t*)(&thread_arg->host->addrlen_tcp)) == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        received = 0;
        continue;
      }
      ft_putendl_fd("ft_nmap: failed to receive packet", 2);
      exit(EXIT_FAILURE);
    }
    if (ntohs(packet.tcp_header.source) == port && scan_port_tcp_finished(&packet, type))
    {
      received = 1;
      break;
    }
  } while (1);
  scan_port_tcp_set_result(&thread_arg->host->results[port], type, &packet, received);
}
