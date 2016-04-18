#include "ft_nmap.h"

char *get_scan_conclusion(t_env *env, t_port_result *result)
{
  if (env->type_syn)
  {
    if (result->status_syn == OPENED)
      return ("Opened");
    else if (result->status_syn == FILTERED)
      return ("Filtered");
    return ("Closed");
  }
  if (env->type_xmas)
  {
    if (result->status_xmas == OPENED_FILTERED)
      return ("Opened|Filtered");
  }
  if (env->type_null)
  {
    if (result->status_null == OPENED_FILTERED)
      return ("Opened|Filtered");
  }
  if (env->type_fin)
  {
    if (result->status_fin == OPENED_FILTERED)
      return ("Opened|Filtered");
  }
  if (env->type_ack)
  {
    if (result->status_ack == FILTERED)
      return ("Filtered");
    else
      return ("Unfiltered");
  }
  return ("Closed");
}
