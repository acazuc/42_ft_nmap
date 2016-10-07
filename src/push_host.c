#include "ft_nmap.h"

void push_host(t_env *env, t_host *host)
{
	t_host **new;
	int len;

	len = 0;
	while (env->hosts[len])
		len++;
	if (!(new = malloc(sizeof(*new) * (len + 2))))
	{
		ft_putendl_fd("ft_nmap: can't malloc new host array", 2);
		exit(EXIT_FAILURE);
	}
	len = 0;
	while (env->hosts[len])
	{
		new[len] = env->hosts[len];
		len++;
	}
	new[len++] = host;
	new[len++] = NULL;
	free(env->hosts);
	env->hosts = new;
}
