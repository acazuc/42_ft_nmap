#include "ft_nmap.h"

void packet_flush_tcp(t_host *host, int port)
{
  t_tcp_packet_list *lst;
  t_tcp_packet_list *prv;

  pthread_mutex_lock(&host->mutex_tcp);
  lst = host->packets_tcp;
  prv = NULL;
  while (lst)
  {
    if (ntohs(lst->packet->tcp_header.source) == port)
    {
      if (!prv)
        host->packets_tcp = lst->next;
      else
        prv->next = lst->next;
      free(lst->packet);
      free(lst);
      if (prv)
        lst = prv->next;
      else
        lst = host->packets_tcp;
    }
    else {
      prv = lst;
      lst = lst->next;
    }
  }
  pthread_mutex_unlock(&host->mutex_tcp);
}

void packet_flush_icmp(t_host *host, int port)
{
  t_icmp_packet_list *lst;
  t_icmp_packet_list *prv;
  uint16_t tmp_port;

  pthread_mutex_lock(&host->mutex_icmp);
  lst = host->packets_icmp;
  prv = NULL;
  while (lst)
  {
    if (lst->packet->icmp_header.type != 3 || lst->packet->icmp_header.code != 3)
    {
      if (!prv)
        host->packets_icmp = lst->next;
      else
        prv->next = lst->next;
      free(lst->packet);
      free(lst);
      continue;
    }
    ft_memcpy(&tmp_port, lst->packet->data + sizeof(struct iphdr) + 2, sizeof(tmp_port));
    tmp_port = ntohs(tmp_port);
    if (tmp_port == (uint16_t)port)
    {
      if (!prv)
        host->packets_icmp = lst->next;
      else
        prv->next = lst->next;
      free(lst->packet);
      free(lst);
    }
    prv = lst;
    lst = lst->next;
  }
  pthread_mutex_unlock(&host->mutex_icmp);
}
