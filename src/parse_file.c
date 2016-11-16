#include "ft_nmap.h"

void parse_file(t_env *env, char *file)
{
	char *content;

	if (env->ips)
	{
		fprintf(stderr, "ft_nmap: already defined ip\n");
		exit(EXIT_FAILURE);
	}
	if (!(content = file_get_contents(file)))
	{
	  	fprintf(stderr, "ft_nmap: can't get '%s' file\n", file);
		exit(EXIT_FAILURE);
	}
	if (!(env->ips = ft_strsplit(content, '\n')))
	{
		fprintf(stderr, "ft_nmap: can't split file ips\n");
		exit(EXIT_FAILURE);
	}
}
