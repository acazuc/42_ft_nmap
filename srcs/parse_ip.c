#include "ft_nmap.h"

void parse_ip(t_env *env, char *ip)
{
  if (env->ips)
  {
    ft_putendl_fd("ft_nmap: already defined ip", 2);
    exit(EXIT_FAILURE);
  }
  if (!(env->ips = malloc(sizeof(*env->ips) * 2)))
  {
    ft_putendl_fd("ft_nmap: can't malloc ip", 2);
    exit(EXIT_FAILURE);
  }
  if (!(env->ips[0] = ft_strdup(ip)))
  {
    ft_putendl_fd("ft_nmap: can't dup ip", 2);
    exit(EXIT_FAILURE);
  }
  env->ips[1] = NULL;
}
