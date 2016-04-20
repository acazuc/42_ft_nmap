#include "ft_nmap.h"

char *get_scan_result_str(char *type, t_port_status result)
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
  if (!(rslt = malloc(strlen(type) + strlen(status) + 3)))
  {
    ft_putendl_fd("ft_nmap: can't malloc result string", 2);
    exit(EXIT_FAILURE);
  }
  ft_bzero(rslt, strlen(type) + strlen(status) + 3);
  rslt = ft_strcat(rslt, type);
  rslt = ft_strcat(rslt, "(");
  rslt = ft_strcat(rslt, status);
  rslt = ft_strcat(rslt, ")");
  return (rslt);
}
