#include "ft_nmap.h"

void parse_file(t_env *env, char *file)
{
  char *content;

  if (env->ips)
  {
    ft_putendl_fd("ft_nmap: already defined ip", 2);
    exit(EXIT_FAILURE);
  }
  if (!(content = file_get_contents(file)))
  {
    ft_putstr_fd("ft_nmap: can't get '", 2);
    ft_putstr_fd(file, 2);
    ft_putendl_fd("' file", 2);
    exit(EXIT_FAILURE);
  }
  if (!(env->ips = ft_strsplit(content, '\n')))
  {
    ft_putendl_fd("ft_nmap: can't split file ips", 2);
    exit(EXIT_FAILURE);
  }
}
