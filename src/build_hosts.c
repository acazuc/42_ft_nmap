#include "ft_nmap.h"

static int build_socket(int *sock, int protocol)
{
	struct timeval tv;
	int val;

	if ((*sock = socket(AF_INET, SOCK_RAW, protocol)) == -1)
		return (0);
	val = 1;
	if (setsockopt(*sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) == -1)
		return (0);
	tv.tv_sec = 0;
	tv.tv_usec = 100;
	if (setsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		return (0);
	return (1);
}

static int build_tcp(t_host *host)
{
	if (!build_socket(&host->socket_tcp, IPPROTO_TCP))
	{
		fprintf(stderr, "ft_nmap: can't connect to '%s' host\n", host->host);
		return (0);
	}
	return (1);
}

static int build_udp(t_host *host)
{
	if (!build_socket(&host->socket_udp, IPPROTO_UDP))
	{
		fprintf(stderr, "ft_nmap: can't connect to '%s' host\n", host->host);
		return (0);
	}
	return (1);
}

static int build_icmp(t_host *host)
{
	if (!build_socket(&host->socket_icmp, IPPROTO_ICMP))
	{
		fprintf(stderr, "ft_nmap: can't connect to '%s' host\n", host->host);
		return (0);
	}
	return (1);
}

static void build_addr(t_host *host)
{
	in_addr_t tmp;

	host->addrlen = sizeof(*host->addr);
	if (!(host->addr = malloc(host->addrlen)))
	{
		fprintf(stderr, "ft_nmap: can't malloc new addr\n");
		exit(EXIT_FAILURE);
	}
	ft_memset(host->addr, 0, host->addrlen);
	host->addr->sa_family = AF_INET;
	if ((tmp = inet_addr(host->ip)) == INADDR_NONE)
	{
		fprintf(stderr, "ft_nmap: can't get binary ip\n");
		exit(EXIT_FAILURE);
	}
	ft_memcpy(host->addr->sa_data + 2, &tmp, sizeof(tmp));
}

static void resolve_ip(t_host *host)
{
	struct hostent *hostent;
	struct in_addr *tmp;

	if (!(hostent = gethostbyname(host->host)))
	{
		fprintf(stderr, "ft_nmap: can't resolve ip\n");
		exit(EXIT_FAILURE);
	}
	if (hostent->h_addrtype != AF_INET)
	{
		fprintf(stderr, "ft_nmap: ip isn't ipv4\n");
		exit(EXIT_FAILURE);
	}
	if (hostent->h_length < 1)
	{
		fprintf(stderr, "ft_nmap: can't resolve ip\n");
		exit(EXIT_FAILURE);
	}
	tmp = (struct in_addr*)hostent->h_addr_list[0];
	if (!(host->ip = inet_ntoa(*tmp)))
	{
		fprintf(stderr, "ft_nmap: can't get ip string\n");
		exit(EXIT_FAILURE);
	}
	host->ip = ft_strdup(host->ip);
}

void build_hosts(t_env *env)
{
	t_host *host;
	int i;

	i = 0;
	while (env->ips[i])
	{
		if (!(host = malloc(sizeof(*host))))
		{
			fprintf(stderr, "ft_nmap: can't malloc host struct\n");
			exit(EXIT_FAILURE);
		}
		ft_memset(host, 0, sizeof(*host));
		host->host = env->ips[i];
		resolve_ip(host);
		if (env->type_syn || env->type_null || env->type_ack || env->type_fin || env->type_xmas)
		{
			if (!build_tcp(host))
			{
				free(host);
				i++;
				continue;
			}
		}
		if (env->type_udp)
		{
			if (!build_udp(host))
			{
				free(host);
				i++;
				continue;
			}
			if (!build_icmp(host))
			{
				free(host);
				i++;
				continue;
			}
		}
		build_addr(host);
		if (pthread_mutex_init(&host->mutex_tcp, NULL) || pthread_mutex_init(&host->mutex_icmp, NULL))
		{
			fprintf(stderr, "ft_nmap: can't init pthread mutex\n");
			exit(EXIT_FAILURE);
		}
		push_host(env, host);
		i++;
	}
}
