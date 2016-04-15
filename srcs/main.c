#include "ft_nmap.h"

int main(int ac, char **av)
{
  t_env env;

  env_init(&env);
  parse_params(&env, ac, av);
  env_default(&env);
  ft_putendl("ips: ");
  int i = 0;
  while (env.ips[i])
  {
    ft_putendl(env.ips[i]);
    i++;
  }
  ft_putendl("ports: ");
  i = 0;
  while (i < 65536)
  {
    if (env.ports[i])
    {
      ft_putnbr(i);
      ft_putchar('\n');
    }
    i++;
  }
  ft_putendl("threads number: ");
  ft_putnbr(env.threads_nb);
  ft_putchar('\n');
  ft_putendl("scan types: ");
  if (env.type_syn)
    ft_putendl("SYN");
  if (env.type_null)
    ft_putendl("NULL");
  if (env.type_acl)
    ft_putendl("ACL");
  if (env.type_fin)
    ft_putendl("FIN");
  if (env.type_xmas)
    ft_putendl("XMAS");
  if (env.type_udp)
    ft_putendl("UDP");
}
