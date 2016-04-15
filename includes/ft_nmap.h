#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "../libft/includes/libft.h"
# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>

typedef struct s_env t_env;

struct s_env
{
  char **ips;
  char ports[65536];
  int threads_nb;
  char type_syn;
  char type_null;
  char type_acl;
  char type_fin;
  char type_xmas;
  char type_udp;
  char defined_ports;
  char defined_speedup;
  char defined_scans;
};

void env_default(t_env *env);
void env_init(t_env *env);
char *file_get_contents(char *file);
void parse_file(t_env *env, char *file);
void parse_ip(t_env *env, char *ip);
void parse_params(t_env *env , int ac, char **av);
void parse_ports(t_env *env, char *ports);
void parse_scan(t_env *env, char *scans);
void parse_speedup(t_env *env, char *speedup);
void print_help(void);
int valid_port(char *port);

#endif
