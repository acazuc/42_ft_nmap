#include "ft_nmap.h"

static void print_scans(t_env *env)
{
  if (env->type_syn)
    ft_putstr(" SYN");
  if (env->type_null)
    ft_putstr(" NULL");
  if (env->type_acl)
    ft_putstr(" ACL");
  if (env->type_fin)
    ft_putstr(" FIN");
  if (env->type_xmas)
    ft_putstr(" XMAS");
  if (env->type_udp)
    ft_putstr(" UDP");
}

void scan_host(t_env *env, char *host)
{
  ft_putendl("Scan Configurations");
  ft_putstr("Target ip address: ");
  ft_putstr(host);
  ft_putchar('\n');
  ft_putstr("Number of ports to scan: ");
  ft_putnbr(get_ports_number(env));
  ft_putchar('\n');
  ft_putstr("Scans to be performed:");
  print_scans(env);
  ft_putchar('\n');
  ft_putstr("Number of threads: ");
  ft_putnbr(env->threads_nb);
  ft_putchar('\n');
}
