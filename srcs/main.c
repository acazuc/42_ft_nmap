#include "ft_nmap.h"


int main(int ac, char **av)
{
  t_env env;

  env_init(&env);
  parse_params(&env, ac, av);
  env_default(&env);
  env_check_port_number(&env);
  print_debug(&env);
  ft_putchar('\n');
  build_hosts(&env);
  int i = 0;
  while (env.hosts[i])
  {
    scan_host(&env, env.hosts[i]);
    i++;
  }
}
