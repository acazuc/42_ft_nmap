#include "ft_nmap.h"

const char *get_color_by_service( char *s )
{
	uint8_t sum = 0;

	if ( !ft_strcmp( s, "unassigned" ) )
		return DARK;

	static const char colors[15][12] =
	{
		GREY,
		RED,
		GREEN,
		YELLOW,
		BLUE,
		MAGENTA,
		CYAN,
		WHITE,
		PINK,
		PEACHY,
		SKY,
		INDIGO,
		PURPLE,
		FOAM,
		SPRING
	};

	while ( *s )
		sum += *s++;

	return colors[sum % 15];
}

static void print_result_port_mult_part(char *type, enum e_port_status status, int i)
{
	char *tmp;

	tmp = get_scan_result_str(type, status);
	if (i == 1)
		printf("%-20s ", tmp);
	else
		printf("\n%-10s %-30s %-86s ", "", "", tmp);
	free(tmp);
}

static void print_result_port_mult(t_env *env, t_port_result *result, int port)
{
	int i;
	char *service = get_service_name(port);

	printf( BLUE "%-10d %s%-30s " WHITE, port, get_color_by_service( service ), service );
	i = 0;
	if (env->type_syn)
		print_result_port_mult_part(RED "SYN", result->status_syn, ++i);
	if (env->type_null)
		print_result_port_mult_part(PEACHY "NULL", result->status_null, ++i);
	if (env->type_ack)
		print_result_port_mult_part(YELLOW "ACK", result->status_ack, ++i);
	if (env->type_fin)
		print_result_port_mult_part(GREEN "FIN", result->status_fin, ++i);
	if (env->type_xmas)
		print_result_port_mult_part(CYAN "XMAS", result->status_xmas, ++i);
	if (env->type_udp)
		print_result_port_mult_part(BLUE "UDP", result->status_udp, ++i);
	printf("%-10s\n\n", get_scan_conclusion(env, result));
}

static void print_result_port(t_env *env, t_port_result *result, int port)
{
	char *tmp;
	char *service = get_service_name(port);

	tmp = NULL;
	if (get_scan_type_number(env) == 1)
	{
		if (env->type_syn)
			tmp = get_scan_result_str(RED "SYN", result->status_syn);
		if (env->type_null)
			tmp = get_scan_result_str(PEACHY "NULL", result->status_null);
		if (env->type_ack)
			tmp = get_scan_result_str(YELLOW "ACK", result->status_ack);
		if (env->type_fin)
			tmp = get_scan_result_str(GREEN "FIN", result->status_fin);
		if (env->type_xmas)
			tmp = get_scan_result_str(CYAN "XMAS", result->status_xmas);
		if (env->type_udp)
			tmp = get_scan_result_str(BLUE "UDP", result->status_udp);
		printf
		(
			BLUE "%-10d %s%-30s %-86s %-10s\n",
			port,
			get_color_by_service( service ),
			service,
			tmp,
			get_scan_conclusion(env, result)
		);
		free(tmp);
	}
	else
		print_result_port_mult(env, result, port);
}

void print_result(t_env *env, t_host *host)
{
	int i;

	printf(GREEN "Open ports" WHITE ":\n");
	printf( BLUE "%-10s" GREEN " %-63s" PEACHY " %-20s" RED " %-10s\n", "Port", "Service Name " WHITE "(" GREEN "if applicable" WHITE ")", "Results", "Conclusion");
	printf(WHITE "%s-%s-%s-%s\n", "----------", "------------------------------", "--------------------", "----------");
	i = 0;
	while (i < 65536)
	{
		if (env->ports[i])
			if (port_status_opened(env, &host->results[i]))
				print_result_port(env, &host->results[i], i);
		i++;
	}
	printf("\n");
	printf(RED "Filtered/Unfiltered/Closed ports" WHITE ":\n");
	printf( BLUE "%-10s" GREEN " %-63s" PEACHY " %-20s" RED " %-10s\n", "Port", "Service Name " WHITE "(" GREEN "if applicable" WHITE ")", "Results", "Conclusion");
	printf(WHITE "%s-%s-%s-%s\n", "----------", "------------------------------", "--------------------", "----------");
	i = 0;
	while (i < 65536)
	{
		if (env->ports[i])
			if (!port_status_opened(env, &host->results[i]))
				print_result_port(env, &host->results[i], i);
		i++;
	}
}
