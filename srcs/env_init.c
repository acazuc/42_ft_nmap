#include "ft_nmap.h"

static void init_hosts(t_env *env)
{
  if (!(env->hosts = malloc(sizeof(*env->hosts))))
  {
    ft_putendl_fd("ft_nmap: can't malloc host array", 2);
    exit(EXIT_FAILURE);
  }
  env->hosts[0] = NULL;
}

static void init_ports(t_env *env)
{
  int i;

  i = 0;
  while (i < 65536)
  {
    env->ports[i] = 0;
    i++;
  }
}

static void init_types(t_env *env)
{
  env->type_syn = 0;
  env->type_null = 0;
  env->type_acl = 0;
  env->type_fin = 0;
  env->type_xmas = 0;
  env->type_udp = 0;
}

static void init_defined(t_env *env)
{
  env->defined_ports = 0;
  env->defined_speedup = 0;
  env->defined_scans = 0;
}

void env_init(t_env *env)
{
  init_hosts(env);
  env->ips = NULL;
  init_ports(env);
  env->threads_nb = 1;
  init_types(env);
  init_defined(env);
}
