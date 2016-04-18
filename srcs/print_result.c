#include "ft_nmap.h"

static void print_result_port_mult_part(char *type, t_port_status status, int i)
{
  char *tmp;

  tmp = get_scan_result_str(type, status);
  if (i == 1)
    printf("%-20s ", tmp);
  else
    printf("\n%-10s %-30s %-20s ", "", "", tmp);
  free(tmp);
}

static void print_result_port_mult(t_env *env, t_port_result *result, int port)
{
  int i;

  printf("%-10d %-30s ", port, get_service_name(port));
  i = 0;
  if (env->type_syn)
    print_result_port_mult_part("SYN", result->status_syn, ++i);
  if (env->type_null)
    print_result_port_mult_part("NULL", result->status_null, ++i);
  if (env->type_ack)
    print_result_port_mult_part("ACK", result->status_ack, ++i);
  if (env->type_fin)
    print_result_port_mult_part("FIN", result->status_fin, ++i);
  if (env->type_xmas)
    print_result_port_mult_part("XMAS", result->status_xmas, ++i);
  printf("%-10s\n", get_scan_conclusion(env, result));
}

static void print_result_port(t_env *env, t_port_result *result, int port)
{
  char *tmp;

  tmp = NULL;
  if (get_scan_type_number(env) == 1)
  {
    if (env->type_syn)
      tmp = get_scan_result_str("SYN", result->status_syn);
    if (env->type_null)
      tmp = get_scan_result_str("NULL", result->status_null);
    if (env->type_ack)
      tmp = get_scan_result_str("ACK", result->status_ack);
    if (env->type_fin)
      tmp = get_scan_result_str("FIN", result->status_fin);
    if (env->type_xmas)
      tmp = get_scan_result_str("XMAS", result->status_xmas);
    if (env->type_udp)
      tmp = get_scan_result_str("UDP", result->status_udp);
    printf("%-10d %-30s %-20s %-10s\n", port, get_service_name(port), tmp, get_scan_conclusion(env, result));
    free(tmp);
  }
  else
    print_result_port_mult(env, result, port);
}

void print_result(t_env *env, t_host *host)
{
  int i;

  printf("Opened ports:\n");
  printf("%-10s %-30s %-20s %-10s\n", "Port", "Service Name (if applicable)", "Results", "Conclusion");
  printf("%s-%s-%s-%s\n", "----------", "------------------------------", "--------------------", "----------");
  i = 0;
  while (i < 65536)
  {
    if (env->ports[i])
      if (port_status_opened(env, &host->results[i]))
        print_result_port(env, &host->results[i], i);
    i++;
  }
  printf("\n");
  printf("Filtered/Unfiltered/Closed ports:\n");
  printf("%-10s %-30s %-20s %-10s\n", "Port", "Service Name (if applicable)", "Results", "Conclusion");
  printf("%s-%s-%s-%s\n", "----------", "------------------------------", "--------------------", "----------");
  i = 0;
  while (i < 65536)
  {
    if (env->ports[i])
      if (!port_status_opened(env, &host->results[i]))
        print_result_port(env, &host->results[i], i);
    i++;
  }
}
