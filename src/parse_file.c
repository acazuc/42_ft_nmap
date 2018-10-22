#include "ft_nmap.h"

void parse_file(t_env *env, char *file)
{
	char *content;

	if (!file)
	{
		fprintf(stderr, RED "ft_nmap: expected file after --file\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (env->ips)
	{
		fprintf(stderr, RED "ft_nmap: already defined ip\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	if (!(content = file_get_contents(file)))
	{
	  	fprintf(stderr, RED "ft_nmap: can't get '%s' file\n" DEFAULT, file);
		exit(EXIT_FAILURE);
	}
	if (!(env->ips = ft_strsplit(content, '\n')))
	{
		fprintf(stderr, RED "ft_nmap: can't split file ips\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
}
