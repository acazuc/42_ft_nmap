#include "ft_nmap.h"

void parse_speedup(t_env *env, char *speedup)
{
  int atoied;

  env->defined_speedup = 1;
  if (!ft_strisdigit(speedup))
  {
    ft_putendl_fd("ft_nmap: invalid speedup value", 2);
    print_help();
  }
  while (speedup[0] == '0')
    speedup++;
  if (ft_strlen(speedup) > 3)
  {
    ft_putendl_fd("ft_nmap: invalid speedup value", 2);
    print_help();
  }
  if ((atoied = ft_atoi(speedup)) > 250 || atoied < 1)
  {
    ft_putendl_fd("ft_nmap: invalid speedup value", 2);
    exit(EXIT_FAILURE);
  }
  env->threads_nb = atoied;
}
