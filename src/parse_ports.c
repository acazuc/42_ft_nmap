#include "ft_nmap.h"

static void add_ports_range(t_env *env, unsigned short start, unsigned short end)
{
	unsigned short i;

	if (start > end)
	{
		i = start;
		start = end;
		end = i;
	}
	i = start;
	while (i <= end)
	{
		env->ports[i] = 1;
		i++;
	}
}

static void parse_port_part(t_env *env, char *part)
{
	char **splitted;

	if (!(splitted = ft_strsplit(part, '-')))
	{
		fprintf(stderr, RED "ft_nmap: can't malloc splitted ports\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (!splitted[0] || splitted[2] || !valid_port(splitted[0]) || (splitted[1] && !valid_port(splitted[1])))
	{
		fprintf(stderr, RED "ft_nmap: invalid ports format\n" DEFAULT);
		print_help();
	}
	if (splitted[1])
		add_ports_range(env, ft_atoi(splitted[0]), ft_atoi(splitted[1]));
	else
		env->ports[ft_atoi(splitted[0])] = 1;
}

void parse_ports(t_env *env, char *ports)
{
	char **splitted;
	int i;

	if (!ports)
	{
		fprintf(stderr, RED "ft_nmap: expected ports after --ports\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	env->defined_ports = 1;
	if (!(splitted = ft_strsplit(ports, ',')))
	{
		fprintf(stderr, RED "ft_nmap: can't malloc splitted ports\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	i = 0;
	while (splitted[i])
	{
		parse_port_part(env, splitted[i]);
		free(splitted[i]);
		i++;
	}
	free(splitted);
}
