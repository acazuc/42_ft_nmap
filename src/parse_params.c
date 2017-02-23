#include "ft_nmap.h"

void parse_params(t_env *env, int ac, char **av)
{
	int i;

	i = 1;
	while (i < ac)
	{
		if (!ft_strcmp(av[i], "--help"))
			print_help();
		else if (!ft_strcmp(av[i], "--ports"))
			parse_ports(env, av[++i]);
		else if (!ft_strcmp(av[i], "--ip"))
			parse_ip(env, av[++i]);
		else if (!ft_strcmp(av[i], "--file"))
			parse_file(env, av[++i]);
		else if (!ft_strcmp(av[i], "--speedup"))
			parse_speedup(env, av[++i]);
		else if (!ft_strcmp(av[i], "--scan"))
			parse_scan(env, av[++i]);
		else
		{
			fprintf(stderr, RED "ft_nmap: unknown argument '%s'\n" DEFAULT, av[i]);
			print_help();
		}
		i++;
	}
}
