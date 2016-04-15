#include "ft_nmap.h"

void env_check_port_number(t_env *env)
{
  if (get_ports_number(env) > 1024)
  {
    ft_putendl_fd("ft_nmap: invalid number of scanned ports", 2);
    print_help();
  }
}
