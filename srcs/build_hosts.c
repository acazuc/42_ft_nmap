#include "ft_nmap.h"

static int resolve_destination(t_host *host, int protocol, struct sockaddr **addr, size_t *addrlen)
{
	struct addrinfo *res;
	struct addrinfo hints;
	char tmp[16];

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = protocol;
	if (getaddrinfo(host->host, NULL, &hints, &res))
		return (0);
	if (!res)
		return (0);
	ft_bzero(tmp, 16);
	if (!inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, tmp, 16))
		return (0);
	host->ip = ft_strdup(tmp);
	*addrlen = res->ai_addrlen;
	if (!(*addr = malloc(res->ai_addrlen)))
	{
		ft_putstr_fd("ft_nmap: can't malloc addr\n", 2);
		exit(EXIT_FAILURE);
	}
	ft_memcpy(*addr, res->ai_addr, res->ai_addrlen);
	return (1);
}

static int build_socket(int *sock, int protocol)
{
	int val;

	if ((*sock = socket(AF_INET, SOCK_RAW, protocol)) == -1)
		return (0);
	val = 1;
	if (setsockopt(*sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) == -1)
		return (0);
	return (1);
}

static int build_tcp(t_host *host)
{
	if (!resolve_destination(host, IPPROTO_TCP, &host->addr_tcp, &host->addrlen_tcp))
	{
		ft_putstr_fd("ft_nmap: can't resolve '", 2);
		ft_putstr_fd(host->host, 2);
		ft_putendl_fd("' host", 2);
		return (0);
	}
	if (!build_socket(&host->socket_tcp, IPPROTO_TCP))
	{
		ft_putstr_fd("ft_nmap: can't connect to '", 2);
		ft_putstr_fd(host->host, 2);
		ft_putendl_fd("' host", 2);
		return (0);
	}
	return (1);
}

static int build_udp(t_host *host)
{
	if (!resolve_destination(host, IPPROTO_UDP, &host->addr_udp, &host->addrlen_udp))
	{
		ft_putstr_fd("ft_nmap: can't resolve '", 2);
		ft_putstr_fd(host->host, 2);
		ft_putendl_fd("' host", 2);
		return (0);
	}
	if (!build_socket(&host->socket_udp, IPPROTO_UDP))
	{
		ft_putstr_fd("ft_nmap: can't connect to '", 2);
		ft_putstr_fd(host->host, 2);
		ft_putendl_fd("' host", 2);
		return (0);
	}
	return (1);
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
			ft_putendl_fd("ft_nmap: can't malloc host struct", 2);
			exit(EXIT_FAILURE);
		}
		host->host = env->ips[i];
		if (env->type_syn || env->type_null || env->type_ack || env->type_fin || env->type_xmas)
			if (!build_tcp(host))
			{
				free(host);
				i++;
				continue;
			}
		if (env->type_udp)
			if (!build_udp(host))
			{
				free(host);
				i++;
				continue;
			}
		push_host(env, host);
		i++;
	}
}
