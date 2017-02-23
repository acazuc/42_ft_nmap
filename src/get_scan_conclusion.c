#include "ft_nmap.h"

char *get_scan_conclusion(t_env *env, t_port_result *result)
{
	if (env->type_syn)
	{
		if (result->status_syn == OPEN)
			return (GREEN "Open");
		else if (result->status_syn == FILTERED)
			return (PEACHY "Filtered");
		return (RED "Closed");
	}
	if (env->type_ack)
	{
		if (result->status_ack == FILTERED)
			return (PEACHY "Filtered");
		else
			return (YELLOW "Unfiltered");
	}
	if (env->type_xmas)
	{
		if (result->status_xmas == OPEN_FILTERED)
			return (PEACHY "Filtered");
	}
	if (env->type_null)
	{
		if (result->status_null == OPEN_FILTERED)
			return (PEACHY "Filtered");
	}
	if (env->type_fin)
	{
		if (result->status_fin == OPEN_FILTERED)
			return (PEACHY "Filtered");
	}
	if (env->type_udp)
	{
		if (result->status_udp == OPEN_FILTERED)
			return (PEACHY "Filtered");
	}
	return (RED "Closed");
}
