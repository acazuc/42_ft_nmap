#include "ft_nmap.h"

t_tcp_packet *packet_get_tcp(t_host *host, int port, uint32_t sequence, char *type)
{
	t_tcp_packet_list *lst;

	pthread_mutex_lock(&host->mutex_tcp);
	lst = host->packets_tcp;
	while (lst)
	{
		if (ntohs(lst->packet->tcp_header.ack_seq) == ntohs(sequence) && ntohs(lst->packet->tcp_header.source) == port && scan_port_tcp_finished(lst->packet, type))
		{
			pthread_mutex_unlock(&host->mutex_tcp);
			return (lst->packet);
		}
		lst = lst->next;
	}
	pthread_mutex_unlock(&host->mutex_tcp);
	return (NULL);
}

int packet_get_icmp(t_host *host, int port)
{
	t_icmp_packet_list *lst;
	uint16_t tmp_port;

	pthread_mutex_lock(&host->mutex_icmp);
	lst = host->packets_icmp;
	while (lst)
	{
		if (lst->packet->icmp_header.type == 3 && lst->packet->icmp_header.code == 3)
		{
			ft_memcpy(&tmp_port, lst->packet->data + sizeof(struct iphdr) + 2, sizeof(tmp_port));
			tmp_port = ntohs(tmp_port);
			if (tmp_port == (uint16_t)port)
			{
				pthread_mutex_unlock(&host->mutex_icmp);
				return (1);
			}
		}
		lst = lst->next;
	}
	pthread_mutex_unlock(&host->mutex_icmp);
	return (0);
}
