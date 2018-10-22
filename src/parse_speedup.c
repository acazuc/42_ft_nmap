#include "ft_nmap.h"

void parse_speedup(t_env *env, char *speedup)
{
	int atoied;

	if (!speedup)
	{
		fprintf(stderr, RED "ft_nmap: expected speedup after --speedup\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	env->defined_speedup = 1;
	if (!ft_strisdigit(speedup))
	{
		fprintf(stderr, RED "ft_nmap: invalid speedup value\n" DEFAULT);
		print_help();
	}
	while (speedup[0] == '0')
		speedup++;
	if (ft_strlen(speedup) > 3 || !speedup[0])
	{
		fprintf(stderr, RED "ft_nmap: invalid speedup value\n" DEFAULT);
		print_help();
	}
	if ((atoied = ft_atoi(speedup)) > 250 || atoied < 1)
	{
		fprintf(stderr, RED "ft_nmap: invalid speedup value\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	env->threads_nb = atoied;
}
