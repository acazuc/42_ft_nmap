#include "ft_nmap.h"

void env_check_port_number(t_env *env)
{
  int number;
  int i;

  number = 0;
  i = 0;
  while (i < 65535)
  {
    if (env->ports[i])
      number++;
    i++;
  }
  if (number > 1024)
  {
    ft_putendl_fd("ft_nmap: invalid number of scanned ports", 2);
    print_help();
  }
}
