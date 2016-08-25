#include "ft_nmap.h"

static void define_ports(t_env *env)
{
	int i;

	i = 1;
	while (i <= 1024)
	{
		env->ports[i] = 1;
		i++;
	}
}

static void define_scans(t_env *env)
{
	env->type_syn = 1;
	env->type_null = 1;
	env->type_ack = 1;
	env->type_fin = 1;
	env->type_xmas = 1;
	env->type_udp = 1;
}

void env_default(t_env *env)
{
	if (!env->defined_ports)
		define_ports(env);
	if (!env->defined_speedup)
		env->threads_nb = 1;
	if (!env->defined_scans)
		define_scans(env);
}
