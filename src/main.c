#include "ft_nmap.h"


int main(int ac, char **av)
{
	t_env env;

	if (getuid())
	{
		ft_putendl_fd("ft_nmap: You must have sudo rights to run this command", 2);
		exit(EXIT_FAILURE);
	}
	env_init(&env);
	parse_params(&env, ac, av);
	if (!env.ips)
	{
		ft_putendl_fd("ft_nmap: You must choose an ip to scan", 2);
		print_help();
		exit(EXIT_FAILURE);
	}
	env_default(&env);
	env_check_port_number(&env);
	resolve_self_ip(&env);
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
