#include "ft_nmap.h"

void parse_params(t_env *env, int ac, char **av)
{
  int i;

  i = 1;
  while (i < ac)
  {
    if (!ft_strcmp(av[i], "--help"))
      print_help();
    else if (!ft_strcmp(av[i], "--ports"))
      parse_ports(env, av[++i]);
    else if (!ft_strcmp(av[i], "--ip"))
      parse_ip(env, av[++i]);
    else if (!ft_strcmp(av[i], "--file"))
      parse_file(env, av[++i]);
    else if (!ft_strcmp(av[i], "--speedup"))
      parse_speedup(env, av[++i]);
    else if (!ft_strcmp(av[i], "--scan"))
      parse_scan(env, av[++i]);
    else
    {
      ft_putstr_fd("ft_nmap: unknown argument '", 2);
      ft_putstr_fd(av[i], 2);
      ft_putstr_fd("'\n", 2);
      print_help();
    }
    i++;
  }
}
