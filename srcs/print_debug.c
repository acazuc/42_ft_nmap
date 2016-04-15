#include "ft_nmap.h"

static void print_hosts(t_env *env)
{
  int i;

  i = 0;
  while (env->ips[i])
  {
    ft_putstr(" '");
    ft_putstr(env->ips[i]);
    ft_putchar('\'');
    i++;
  }
}

static void print_scans(t_env *env)
{
  if (env->type_syn)
    ft_putstr(" SYN");
  if (env->type_null)
    ft_putstr(" NULL");
  if (env->type_ack)
    ft_putstr(" ACK");
  if (env->type_fin)
    ft_putstr(" FIN");
  if (env->type_xmas)
    ft_putstr(" XMAS");
  if (env->type_udp)
    ft_putstr(" UDP");
}

void print_debug(t_env *env)
{
    ft_putendl("Scan Configurations");
    ft_putstr("Target ip address: ");
    print_hosts(env);
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
