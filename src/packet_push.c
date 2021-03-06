#include "ft_nmap.h"

void packet_push_tcp(t_host *host, t_tcp_packet *packet)
{
	t_tcp_packet_list *new;

	pthread_mutex_lock(&host->mutex_tcp);
	if (host->scanning[ntohs(packet->tcp_header.source)])
	{
		if (!(new = malloc(sizeof(*new))))
		{
			fprintf(stderr, RED "Can't malloc new packet list\n" DEFAULT);
			exit(EXIT_FAILURE);
		}
		new->packet = packet;
		new->next = host->packets_tcp;
		host->packets_tcp = new;
	}
	else
		free(packet);
	pthread_mutex_unlock(&host->mutex_tcp);
}

void packet_push_icmp(t_host *host, t_icmp_packet *packet)
{
	t_icmp_packet_list *new;
	uint16_t tmp_port;

	if (packet->icmp_header.code == 3 && packet->icmp_header.type == 3)
	{
		ft_memcpy(&tmp_port, packet->data + sizeof(struct iphdr) + 2, sizeof(tmp_port));
		tmp_port = ntohs(tmp_port);
		pthread_mutex_lock(&host->mutex_icmp);
		if (host->scanning[tmp_port])
		{
			if (!(new = malloc(sizeof(*new))))
			{
				fprintf(stderr, RED "Can't malloc new packet list\n" DEFAULT);
				exit(EXIT_FAILURE);
			}
			new->packet = packet;
			new->next = host->packets_icmp;
			host->packets_icmp = new;
		}
		pthread_mutex_unlock(&host->mutex_icmp);
	}
}
