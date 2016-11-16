#include "ft_nmap.h"

void parse_ip(t_env *env, char *ip)
{
	if (env->ips)
	{
 		fprintf(stderr, "ft_nmap: already defined ip\n");
		exit(EXIT_FAILURE);
	}
	if (!(env->ips = malloc(sizeof(*env->ips) * 2)))
	{
		fprintf(stderr, "ft_nmap: can't malloc ip\n");
		exit(EXIT_FAILURE);
	}
	if (!(env->ips[0] = ft_strdup(ip)))
	{
		fprintf(stderr, "ft_nmap: can't dup ip\n");
		exit(EXIT_FAILURE);
	}
	env->ips[1] = NULL;
}
