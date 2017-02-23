#include "ft_nmap.h"

static void add_scan(t_env *env, char *scan)
{
	if (!ft_strcmp(scan, "SYN"))
		env->type_syn = 1;
	else if (!ft_strcmp(scan, "NULL"))
		env->type_null = 1;
	else if (!ft_strcmp(scan, "ACK"))
		env->type_ack = 1;
	else if (!ft_strcmp(scan, "FIN"))
		env->type_fin = 1;
	else if (!ft_strcmp(scan, "XMAS"))
		env->type_xmas = 1;
	else if (!ft_strcmp(scan, "UDP"))
		env->type_udp = 1;
	else
	{
		fprintf(stderr, RED "ft_nmap: invalid scan type\n" DEFAULT);
		print_help();
	}
}

void parse_scan(t_env *env, char *scans)
{
	char **splitted;
	int i;

	env->defined_scans = 1;
	if (!(splitted = ft_strsplit(scans, ',')))
	{
		fprintf(stderr, RED "ft_nmap: can't split scans value\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (!(splitted[0]))
	{
		fprintf(stderr, RED "ft_nmap: must specify at least one scan type\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	i = 0;
	while (splitted[i])
	{
		add_scan(env, splitted[i]);
		i++;
	}
}
