#include "ft_nmap.h"

static pcap_t *pcap_obj = NULL;

void sigalrm_handler(int sig)
{
	(void)sig;
	pcap_breakloop(pcap_obj);
}

static t_tcp_packet *packet_tcp_alloc(void)
{
	t_tcp_packet *packet;

	if (!(packet = malloc(sizeof(*packet))))
	{
		ft_putendl_fd("ft_nmap: can't malloc packet", 2);
		exit(EXIT_FAILURE);
	}
	return (packet);
}

static t_icmp_packet *packet_icmp_alloc(void)
{
	t_icmp_packet *packet;

	if (!(packet = malloc(sizeof(*packet))))
	{
		ft_putendl_fd("ft_nmap: can't malloc packet", 2);
		exit(EXIT_FAILURE);
	}
	return (packet);
}

static void packet_callback(u_char *tmp, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)pkthdr;
	t_thread_arg *arg;
	unsigned short ethertype;
	struct iphdr iphdr;
	int etherlen = 14;

	(void)arg;
	arg = (t_thread_arg*)tmp;
	if (pkthdr->caplen < 14 + sizeof(iphdr))
		return;
	ft_memcpy(&ethertype, packet + 12, sizeof(ethertype));
	if (ntohs(ethertype) == 0x8100 || !ethertype)
		etherlen = 16;
	else if (ntohs(ethertype) != 0x0800)
		return;
	memcpy(&iphdr, packet + etherlen, sizeof(iphdr));
	if (iphdr.saddr != ((struct sockaddr_in*)arg->host->addr)->sin_addr.s_addr)
		return;
	if (iphdr.protocol == IPPROTO_TCP)
	{
		t_tcp_packet *tcp_packet = packet_tcp_alloc();
		if (pkthdr->caplen < etherlen + sizeof(*tcp_packet))
			return;
		ft_memcpy(tcp_packet, packet + etherlen, sizeof(*tcp_packet));
		if (tcp_packet->tcp_header.dest == htons(arg->env->port))
		{
			packet_push_tcp(arg->host, tcp_packet);
		}
	}
	else if (iphdr.protocol == IPPROTO_ICMP)
	{
		t_icmp_packet *icmp_packet = packet_icmp_alloc();
		if (pkthdr->caplen < etherlen + sizeof(*icmp_packet))
			return;
		ft_memcpy(icmp_packet, packet + etherlen, sizeof(*icmp_packet));
		packet_push_icmp(arg->host, icmp_packet);
	}
}

void *port_listener(void *data)
{
	t_thread_arg *arg;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct bpf_program fp;
	char *str;

	(void)arg;
	arg = (t_thread_arg*)data;
	if (pcap_lookupnet("any", &netp, &maskp, errbuf) == -1)
	{
		ft_putstr_fd("ft_nmap: pcap_lookupnet failed: ", 2);
		ft_putendl_fd(errbuf, 2);
		exit(EXIT_FAILURE);
	}
	if (!(pcap_obj = pcap_open_live("any", BUFSIZ, 0, -1, errbuf)))
	{
		ft_putstr_fd("ft_nmap: pcap_open_live failed: ", 2);
		ft_putendl_fd(errbuf, 2);
		exit(EXIT_FAILURE);
	}
	if (!(str = ft_strjoin("host ", arg->host->ip)))
	{
		ft_putendl_fd("ft_nmap: ft_strjoin failed", 2);
		exit(EXIT_FAILURE);
	}
	if (!(str = ft_strjoin_free1(str, " and (tcp or icmp)")))
	{
		ft_putendl_fd("ft_nmap: ft_strjoin failed", 2);
		exit(EXIT_FAILURE);
	}
	if (pcap_compile(pcap_obj, &fp, str, 1, netp) == -1)
	{
		ft_putstr_fd("ft_nmap: pcap_compile failed", 2);
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(pcap_obj, &fp) == -1)
	{
		ft_putstr_fd("ft_nmap: pcap_setfilter failed", 2);
		exit(EXIT_FAILURE);
	}
	signal(SIGALRM, sigalrm_handler);
	if (pcap_loop(pcap_obj, -1, packet_callback, (u_char*)data) == -1)
	{
		ft_putstr_fd("ft_nmap: pcap_loop failed", 2);
		exit(EXIT_FAILURE);
	}
	free(str);
	return (NULL);
}
