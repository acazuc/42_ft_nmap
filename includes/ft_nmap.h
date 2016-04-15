#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "../libft/includes/libft.h"
# include <sys/socket.h>
# include <netinet/in.h>
# include <linux/tcp.h>
# include <linux/udp.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <linux/ip.h>
# include <netdb.h>
# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <stdio.h>

typedef struct s_env t_env;
typedef struct s_host t_host;
typedef struct s_tcp_packet t_tcp_packet;
typedef struct s_udp_packet t_udp_packet;

struct s_env
{
  t_host **hosts;
  char **ips;
  char ports[65536];
  int threads_nb;
  char type_syn;
  char type_null;
  char type_ack;
  char type_fin;
  char type_xmas;
  char type_udp;
  char defined_ports;
  char defined_speedup;
  char defined_scans;
};

struct s_host
{
  char *host;
  char *ip;
  int socket_tcp;
  int socket_udp;
  struct sockaddr *addr_tcp;
  struct sockaddr *addr_udp;
	size_t addrlen_tcp;
	size_t addrlen_udp;
};

struct s_tcp_packet
{
  struct iphdr ip_header;
	struct tcphdr tcp_header;
};

struct s_udp_packet
{
  struct iphdr ip_header;
	struct udphdr udp_header;
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
void env_check_port_number(t_env *env);
int get_ports_number(t_env *env);
void scan_host(t_env *env, t_host *host);
void print_debug(t_env *env);
void build_hosts(t_env *env);
void push_host(t_env *env, t_host *host);
uint16_t ip_checksum(void *addr, size_t len);
void forge_iphdr(struct iphdr *header, int protocol, int pton_addr, size_t packlen);
void forge_tcphdr_syn(struct tcphdr *header, int16_t port);
void forge_tcphdr_null(struct tcphdr *header, int16_t port);
void forge_tcphdr_ack(struct tcphdr *header, int16_t port);
void forge_tcphdr_fin(struct tcphdr *header, int16_t port);
void forge_tcphdr_xmas(struct tcphdr *header, int16_t port);
void forge_udphdr(struct udphdr *header, int16_t port);

#endif
