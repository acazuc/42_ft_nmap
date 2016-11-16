#include "ft_nmap.h"

static void print_hosts(t_env *env)
{
	int i;

	i = 0;
	while (env->ips[i])
	{
		printf(" '%s'", env->ips[i]);
		i++;
	}
}

static void print_scans(t_env *env)
{
	if (env->type_syn)
		printf(" SYN");
	if (env->type_null)
		printf(" NULL");
	if (env->type_ack)
		printf(" ACK");
	if (env->type_fin)
		printf(" FIN");
	if (env->type_xmas)
		printf(" XMAS");
	if (env->type_udp)
		printf(" UDP");
}

void print_debug(t_env *env)
{
	printf("Scan Configurations\nTarget ip addresses: ");
	print_hosts(env);
	printf("\nNumber of ports to scan: %d\nScans to be performed:", get_ports_number(env));
	print_scans(env);
	printf("\nNumber of threads: %d\n", env->threads_nb);
}
