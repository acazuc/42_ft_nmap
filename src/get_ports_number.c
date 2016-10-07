#include "ft_nmap.h"

int get_ports_number(t_env *env)
{
	int number;
	int i;

	number = 0;
	i = 0;
	while (i < 65535)
	{
		if (env->ports[i])
			number++;
		i++;
	}
	return (number);
}
