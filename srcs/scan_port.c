#include "ft_nmap.h"

void scan_port(t_thread_arg *thread_arg, int port)
{
  ft_putstr("scanning port ");
  ft_putnbr(port);
  ft_putchar('\n');
  (void)thread_arg;
  (void)port;
}
