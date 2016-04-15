#include "ft_nmap.h"

static void fill_ports(t_thread_arg *thread_arg, char *ports)
{
  int number;
  int total;
  int i;

  total = get_ports_number(thread_arg->env);
  i = 0;
  number = 0;
  while (i < 65536)
  {
    if (thread_arg->env->ports[i])
    {
      if (number >= thread_arg->thread_id * total / thread_arg->total_threads
      && (number < (thread_arg->thread_id + 1) * total / thread_arg->total_threads
        || (thread_arg->thread_id == total && number == total - 1)))
        ports[i] = 1;
      number++;
    }
    i++;
  }
}

void *thread_run(void *data)
{
  t_thread_arg *thread_arg;
  char ports[65536];
  int i;

  thread_arg = (t_thread_arg*)data;
  ft_putstr("Thread running..\n");
  ft_bzero(ports, sizeof(ports));
  fill_ports(thread_arg, &(ports[0]));
  i = 0;
  while (i < 65536)
  {
    if (ports[i])
    {
      scan_port(thread_arg, i);
    }
    i++;
  }
  return (NULL);
}
