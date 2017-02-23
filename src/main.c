#include "ft_nmap.h"

int main(int ac, char **av)
{
	t_env env;

	if (getuid())
	{
		fprintf(stderr, RED "ft_nmap: You must have sudo rights to run this command\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	env_init(&env);
	parse_params(&env, ac, av);
	if (!env.ips)
	{
		fprintf(stderr, RED "ft_nmap: You must choose an ip to scan\n" DEFAULT);
		print_help();
		exit(EXIT_FAILURE);
	}
	env_default(&env);
	env_check_port_number(&env);
	resolve_self_ip(&env);
	reserve_port(&env);
	print_debug(&env);
	build_hosts(&env);
	int i = 0;
	while (env.hosts[i])
	{
		scan_host(&env, env.hosts[i]);
		i++;
	}
	return (EXIT_SUCCESS);
}
