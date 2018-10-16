#include "ft_nmap.h"

char *get_service_name(uint16_t port)
{
	struct servent *result;

	result = getservbyport(htons(port), NULL);
	if (!result)
		return ("unassigned");
	return (result->s_name);
}
