#include "ft_nmap.h"

void scan_port(t_thread_arg *thread_arg, int port)
{
	struct iphdr ip_header;
	int32_t pton_addr;

	if (inet_pton(AF_INET, thread_arg->host->ip, &pton_addr) != 1)
	{
		fprintf(stderr, RED "ft_nmap: can't inet_pton ip\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_lock(&thread_arg->host->mutex_tcp);
	thread_arg->host->scanning[port] = 1;
	pthread_mutex_unlock(&thread_arg->host->mutex_tcp);
	if (thread_arg->env->type_syn || thread_arg->env->type_null || thread_arg->env->type_ack
			|| thread_arg->env->type_fin || thread_arg->env->type_xmas)
	{
		forge_iphdr(&ip_header, IPPROTO_TCP, pton_addr, sizeof(t_tcp_packet));
		if (thread_arg->env->type_syn)
			scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_syn, port, "SYN");
		if (thread_arg->env->type_fin)
			scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_fin, port, "FIN");
		if (thread_arg->env->type_null)
			scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_null, port, "NULL");
		if (thread_arg->env->type_xmas)
			scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_xmas, port, "XMAS");
		if (thread_arg->env->type_ack)
			scan_port_tcp(thread_arg, &ip_header, forge_tcphdr_ack, port, "ACK");
	}
	if (thread_arg->env->type_udp)
	{
		forge_iphdr(&ip_header, IPPROTO_UDP, pton_addr, sizeof(t_udp_packet));
		scan_port_udp(thread_arg, &ip_header, port);
	}
	pthread_mutex_lock(&thread_arg->host->mutex_tcp);
	thread_arg->host->scanning[port] = 0;
	pthread_mutex_unlock(&thread_arg->host->mutex_tcp);
}
