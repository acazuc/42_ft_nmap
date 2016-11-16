#include "ft_nmap.h"

char *get_scan_result_str(char *type, enum e_port_status result)
{
	char *status;
	char *rslt;

	status = "";
	if (result == OPEN)
		status = "Open";
	else if (result == FILTERED)
		status = "Filtered";
	else if (result == CLOSED)
		status = "Closed";
	else if (result == UNFILTERED)
		status = "Unfiltered";
	else if (result == OPEN_FILTERED)
		status = "Open|Filtered";
	if (!(rslt = malloc(ft_strlen(type) + ft_strlen(status) + 3)))
	{
		fprintf(stderr, "ft_nmap: can't malloc result string\n");
		exit(EXIT_FAILURE);
	}
	ft_memset(rslt, 0, ft_strlen(type) + ft_strlen(status) + 3);
	rslt = ft_strcat(rslt, type);
	rslt = ft_strcat(rslt, "(");
	rslt = ft_strcat(rslt, status);
	rslt = ft_strcat(rslt, ")");
	return (rslt);
}
