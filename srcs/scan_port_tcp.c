#include "ft_nmap.h"

void scan_port_tcp(t_thread_arg *thread_arg, struct iphdr *ip_header, void (*forge_tcphdr)(t_tcp_packet *packet, struct tcphdr *header, int16_t port), int port, char *type)
{
  t_tcp_packet packet;
  size_t started;
  int received;

  packet.ip_header = *ip_header;
  forge_tcphdr(&packet, &packet.tcp_header, port);
  if (sendto(thread_arg->host->socket_tcp, &packet, sizeof(packet), 0, thread_arg->host->addr_tcp, thread_arg->host->addrlen_tcp) == -1)
  {
    ft_putendl_fd("ft_nmap: failed to send packet", 2);
    exit(EXIT_FAILURE);
  }
  started = epoch_micro();
  received = 1;
  do {
    if (recvfrom(thread_arg->host->socket_tcp, &packet, sizeof(packet), 0, thread_arg->host->addr_tcp, (socklen_t*)(&thread_arg->host->addrlen_tcp)) == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        received = 0;
        break;
      }
      ft_putendl_fd("ft_nmap: failed to receive packet", 2);
      exit(EXIT_FAILURE);
    }
    debug_tcp_packet(&packet);
    if (epoch_micro() - started > 1000000)
      break;
  } while (ntohs(packet.tcp_header.source) != port && !scan_port_tcp_finished(&packet, type));
  scan_port_tcp_set_result(&thread_arg->host->results[port], type, &packet, received);
}
