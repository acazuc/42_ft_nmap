#include "ft_nmap.h"

char *get_service_name(int port)
{
  struct servent *result;

  result = getservbyport(htons(port), NULL);
  if (!result)
    return ("Unassigned");
  return (result->s_name);
}
