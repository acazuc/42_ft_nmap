#include "ft_nmap.h"

char *get_scan_result_str(char *type, enum e_port_status result)
{
	char *status;
	char *rslt;

	if (result == OPEN)
		status = WHITE "(" GREEN "Open" WHITE WHITE WHITE ")";
	else if (result == FILTERED)
		status = WHITE "(" PEACHY "Filtered" WHITE WHITE WHITE ")";
	else if (result == CLOSED)
		status = WHITE "(" RED "Closed" WHITE WHITE WHITE ")";
	else if (result == UNFILTERED)
		status = WHITE "(" YELLOW "Unfiltered" WHITE WHITE WHITE ")";
	else if (result == OPEN_FILTERED)
		status = WHITE "(" GREEN "Open" WHITE "|" PEACHY "Filtered" WHITE ")";
	else	
		status = "";
	if (!(rslt = malloc(ft_strlen(type) + ft_strlen(status) + 1)))
	{
		fprintf(stderr, RED "ft_nmap: can't malloc result string\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	ft_memset(rslt, 0, ft_strlen(type) + ft_strlen(status) + 1);
	rslt = ft_strcat(rslt, type);
	rslt = ft_strcat(rslt, status);
	return (rslt);
}
