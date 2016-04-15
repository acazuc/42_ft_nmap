#include "ft_nmap.h"

void *thread_run(void *data)
{
  t_thread_arg *thread_arg;

  thread_arg = (t_thread_arg*)data;
  ft_putstr("Thread running..\n");
  (void)thread_arg;
  return (NULL);
}
