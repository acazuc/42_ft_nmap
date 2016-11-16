#include "ft_nmap.h"

void parse_speedup(t_env *env, char *speedup)
{
	int atoied;

	env->defined_speedup = 1;
	if (!ft_strisdigit(speedup))
	{
		fprintf(stderr, "ft_nmap: invalid speedup value\n");
		print_help();
	}
	while (speedup[0] == '0')
		speedup++;
	if (ft_strlen(speedup) > 3 || !speedup[0])
	{
		fprintf(stderr, "ft_nmap: invalid speedup value\n");
		print_help();
	}
	if ((atoied = ft_atoi(speedup)) > 250 || atoied < 1)
	{
		fprintf(stderr, "ft_nmap: invalid speedup value\n");
		exit(EXIT_FAILURE);
	}
	env->threads_nb = atoied;
}
