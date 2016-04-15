#include "ft_nmap.h"

static void init_buff_result(char **buff, char **result)
{
  if (!(*buff = malloc(sizeof(**buff) * 1001)))
  {
    ft_putendl_fd("ft_nmap: can't malloc file buffer", 2);
    exit(EXIT_FAILURE);
  }
  if (!(*result = malloc(sizeof(**result))))
  {
    ft_putendl_fd("ft_nmap: can't malloc file content", 2);
    exit(EXIT_FAILURE);
  }
  *result[0] = '\0';
  ft_bzero(*buff, 1001);
}

static ssize_t loop_read(char **result, char **buff, int fd)
{
  ssize_t readed;

  while ((readed = read(fd, *buff, 1000)) > 0)
  {
    if (!(*result = ft_strjoin_free1(*result, *buff)))
    {
      ft_putendl_fd("ft_mnap: can't malloc file content", 2);
      exit(EXIT_FAILURE);
    }
    ft_bzero(*buff, 1001);
  }
  return (readed);
}

static void check_error(ssize_t readed, char *file)
{
  if (readed == -1)
  {
    ft_putstr_fd("ft_nmap: error while reading '", 2);
    ft_putstr_fd(file, 2);
    ft_putendl_fd("' file", 2);
    exit(EXIT_FAILURE);
  }
}

char *file_get_contents(char *file)
{
  ssize_t readed;
  char *result;
  char *buff;
  int fd;

  if ((fd = open(file, O_RDONLY)) == -1)
  {
    ft_putstr_fd("ft_nmap: can't open '", 2);
    ft_putstr_fd(file, 2);
    ft_putendl_fd("' file", 2);
    exit(EXIT_FAILURE);
  }
  buff = NULL;
  result = NULL;
  init_buff_result(&buff ,&result);
  readed = loop_read(&result, &buff, fd);
  check_error(readed, file);
  free(buff);
  return (result);
}
