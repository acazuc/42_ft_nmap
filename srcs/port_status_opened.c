#include "ft_nmap.h"

int port_status_opened(t_env *env, t_port_result *result)
{
	if (env->type_syn)
	{
		if (result->status_syn == OPEN)
			return (1);
	}
	return (0);
}
