#include "ft_nmap.h"

void env_check_port_number(t_env *env)
{
	if (get_ports_number(env) > 1024)
	{
		fprintf(stderr, RED "ft_nmap: invalid number of scanned ports\n" DEFAULT);
		print_help();
	}
}
