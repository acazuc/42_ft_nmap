#include "ft_nmap.h"

void parse_ip(t_env *env, char *ip)
{
	if (!ip)
	{
		fprintf(stderr, RED "ft_nmap: expected ips after --ip\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (env->ips)
	{
 		fprintf(stderr, RED "ft_nmap: already defined ip\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (!(env->ips = malloc(sizeof(*env->ips) * 2)))
	{
		fprintf(stderr, RED "ft_nmap: can't malloc ip\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (!(env->ips[0] = ft_strdup(ip)))
	{
		fprintf(stderr, RED "ft_nmap: can't dup ip\n" DEFALUT);
		exit(EXIT_FAILURE);
	}
	env->ips[1] = NULL;
}
