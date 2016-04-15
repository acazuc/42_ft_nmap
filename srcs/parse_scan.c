#include "ft_nmap.h"

static void add_scan(t_env *env, char *scan)
{
  if (!ft_strcmp(scan, "SYN"))
    env->type_syn = 1;
  else if (!ft_strcmp(scan, "NULL"))
    env->type_null = 1;
  else if (!ft_strcmp(scan, "ACK"))
    env->type_ack = 1;
  else if (!ft_strcmp(scan, "FIN"))
    env->type_fin = 1;
  else if (!ft_strcmp(scan, "XMAS"))
    env->type_xmas = 1;
  else if (!ft_strcmp(scan, "UDP"))
    env->type_udp = 1;
  else
  {
    ft_putendl_fd("ft_nmap: invalid scan type", 2);
    print_help();
  }
}

void parse_scan(t_env *env, char *scans)
{
  char **splitted;
  int i;

  env->defined_scans = 1;
  if (!(splitted = ft_strsplit(scans, ',')))
  {
    ft_putendl_fd("ft_nmap: can't split scans value", 2);
    exit(EXIT_FAILURE);
  }
  if (!(splitted[0]))
  {
    ft_putendl_fd("ft_nmap: must specify at least one scan type", 2);
    exit(EXIT_FAILURE);
  }
  i = 0;
  while (splitted[i])
  {
    add_scan(env, splitted[i]);
    i++;
  }
}
