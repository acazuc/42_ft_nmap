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
		printf(RED " SYN");
	if (env->type_null)
		printf(PEACHY " NULL");
	if (env->type_ack)
		printf(YELLOW" ACK");
	if (env->type_fin)
		printf(GREEN" FIN");
	if (env->type_xmas)
		printf(SKY" XMAS");
	if (env->type_udp)
		printf(BLUE" UDP");
}

void print_debug(t_env *env)
{
	printf(SKY "Scan Configurations\n" GREY "Target ip addresses" WHITE ": " GREEN);
	print_hosts(env);
	printf(GREY "\nNumber of ports to scan" WHITE ": " BLUE "%d"
		GREY "\nScans to be performed" WHITE ":", get_ports_number(env));
	print_scans(env);
	printf(GREY "\nNumber of threads" WHITE ": " RED "%d\n", env->threads_nb);
}
