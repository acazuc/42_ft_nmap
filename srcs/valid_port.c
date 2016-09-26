#include "ft_nmap.h"

int valid_port(char *port)
{
	int atoied;

	if (!ft_strisdigit(port))
		return (0);
	while (port[0] == '0')
		port++;
	if (ft_strlen(port) > 5)
		return (0);
	if ((atoied = ft_atoi(port)) < 1 || atoied > 65535)
		return (0);
	return (1);
}
