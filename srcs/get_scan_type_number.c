#include "ft_nmap.h"

int get_scan_type_number(t_env *env)
{
  int number;

  number = 0;
  if (env->type_syn)
    number++;
  if (env->type_null)
    number++;
  if (env->type_ack)
    number++;
  if (env->type_fin)
    number++;
  if (env->type_xmas)
    number++;
  if (env->type_udp)
    number++;
  return (number);
}
