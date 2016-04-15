#include "ft_nmap.h"

static void run_threads(t_env *env, t_host *host)
{
  int thread_nb = get_ports_number(env) < env->threads_nb ? get_ports_number(env) : env->threads_nb;
  pthread_t threads[thread_nb];
  t_thread_arg thread_args[thread_nb];
  int i;

  i = 0;
  while (i < thread_nb)
  {
    thread_args[i].env = env;
    thread_args[i].host = host;
    thread_args[i].total_threads = thread_nb;
    thread_args[i].thread_id = i;
    if (pthread_create(&threads[i], NULL, &thread_run, &thread_args[i]))
    {
      ft_putendl_fd("ft_nmap: can't create thread", 2);
      exit(EXIT_FAILURE);
    }
    i++;
  }
  i = 0;
  while (i < thread_nb)
  {
    pthread_join(threads[i], NULL);
    i++;
  }
}

void scan_host(t_env *env, t_host *host)
{
  ft_putstr("Scanning ");
  ft_putstr(host->ip);
  if (ft_strcmp(host->ip, host->host))
  {
    ft_putstr(" (");
    ft_putstr(host->host);
    ft_putchar(')');
  }
  ft_putchar('\n');
  run_threads(env, host);
}
