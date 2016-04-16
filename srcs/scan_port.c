#include "ft_nmap.h"

static void scan_port_udp(t_thread_arg *thread_arg, struct iphdr *ip_header, int port)
{
  t_udp_packet packet;

  packet.ip_header = *ip_header;
  forge_udphdr(&packet.udp_header, port);
  if (sendto(thread_arg->host->socket_udp, &packet, sizeof(packet), 0, thread_arg->host->addr_udp, thread_arg->host->addrlen_udp) == -1)
  {
    ft_putendl_fd("ft_nmap: failed to send packet", 2);
    perror("ft_nmap");
    exit(EXIT_FAILURE);
  }
}

void scan_port(t_thread_arg *thread_arg, int port)
{
  struct iphdr ip_header;
  int32_t pton_addr;

  ft_putstr("scanning port ");
  ft_putnbr(port);
  ft_putchar('\n');
  if (inet_pton(AF_INET, thread_arg->host->ip, &pton_addr) != 1)
  {
    ft_putendl_fd("ft_nmap: can't inet_pton ip", 2);
    exit(EXIT_FAILURE);
  }
  if (thread_arg->env->type_syn || thread_arg->env->type_null || thread_arg->env->type_ack
  || thread_arg->env->type_fin || thread_arg->env->type_xmas)
  {
    forge_iphdr(&ip_header, IPPROTO_TCP, pton_addr, sizeof(t_tcp_packet));
    if (thread_arg->env->type_null)
      scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_null, port, "NULL");
    if (thread_arg->env->type_ack)
      scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_ack, port, "ACK");
    if (thread_arg->env->type_xmas)
      scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_xmas, port, "XMAS");
    if (thread_arg->env->type_fin)
      scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_fin, port, "FIN");
    if (thread_arg->env->type_syn)
      scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_syn, port, "SYN");
  }
  if (thread_arg->env->type_udp)
  {
    forge_iphdr(&ip_header, IPPROTO_UDP, pton_addr, sizeof(t_udp_packet));
    scan_port_udp(thread_arg, &ip_header, port);
  }
}
