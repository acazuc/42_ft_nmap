#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "../libft/include/libft.h"
# include <netinet/if_ether.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <linux/icmp.h>
# include <linux/tcp.h>
# include <linux/udp.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/time.h>
# include <linux/ip.h>
# include <pthread.h>
# include <ifaddrs.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdint.h>
# include <limits.h>
# include <signal.h>
# include <errno.h>
# include <netdb.h>
# include <fcntl.h>
# include <stdio.h>
# include <poll.h>
# include <pcap.h>

typedef struct s_env t_env;
typedef struct s_host t_host;
typedef struct s_tcp_packet t_tcp_packet;
typedef struct s_udp_packet t_udp_packet;
typedef struct s_icmp_packet t_icmp_packet;
typedef struct s_thread_arg t_thread_arg;
typedef struct s_port_result t_port_result;
typedef struct s_tcp_packet_list t_tcp_packet_list;
typedef struct s_icmp_packet_list t_icmp_packet_list;
typedef struct s_ping_packet t_ping_packet;

struct s_env
{
	t_host **hosts;
	char **ips;
	char ports[USHRT_MAX + 1];
	int threads_nb;
	int local_ip;
	unsigned short port;
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

enum e_port_status
{
	OPEN,
	FILTERED,
	CLOSED,
	UNFILTERED,
	OPEN_FILTERED
};

struct s_port_result
{
	enum e_port_status status_syn;
	enum e_port_status status_null;
	enum e_port_status status_ack;
	enum e_port_status status_fin;
	enum e_port_status status_xmas;
	enum e_port_status status_udp;
};

struct s_host
{
	char *host;
	char *ip;
	int socket_tcp;
	int socket_udp;
	int socket_icmp;
	struct sockaddr *addr;
	size_t addrlen;
	t_port_result results[USHRT_MAX + 1];
	char scanning[USHRT_MAX + 1];
	t_tcp_packet_list *packets_tcp;
	t_icmp_packet_list *packets_icmp;
	pthread_mutex_t mutex_tcp;
	pthread_mutex_t mutex_icmp;
	char ended;
};

struct s_tcp_packet_list
{
	t_tcp_packet *packet;
	t_tcp_packet_list *next;
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

struct s_icmp_packet_list
{
	t_icmp_packet *packet;
	t_icmp_packet_list *next;
};

struct s_icmp_packet
{
	struct iphdr ip_header;
	struct icmphdr icmp_header;
	char data[sizeof(struct iphdr) + 64];
};

struct s_ping_packet
{
	struct iphdr ip_header;
	struct icmphdr icmp_header;
	char data[56];
};

struct s_thread_arg
{
	t_env *env;
	t_host *host;
	int total_threads;
	int thread_id;
};

struct tcp_psdhdr
{
	uint32_t source;
	uint32_t dest;
	uint8_t blank;
	uint8_t protocol;
	uint16_t len;
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
void forge_tcphdr_syn(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr);
void forge_tcphdr_null(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr);
void forge_tcphdr_ack(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr);
void forge_tcphdr_fin(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr);
void forge_tcphdr_xmas(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr);
void forge_udphdr(t_env *env, t_udp_packet *packet, int16_t port, int pton_addr);
void *thread_run(void *data);
void scan_port(t_thread_arg *thread_arg, int port);
int16_t tcp_checksum(t_tcp_packet *packet, int pton_addr);
void scan_port_tcp(t_thread_arg *thread_arg, struct iphdr *ip_header, void (*forge_tcphdr)(t_env *env, t_tcp_packet *packet, int16_t port, int pton_addr), int port, char *type);
int scan_port_tcp_finished(t_tcp_packet *packet, char *type);
void scan_port_tcp_set_result(t_port_result *result, char *type, t_tcp_packet *packet, int received);
size_t epoch_micro(void);
void print_result(t_env *env, t_host *host);
int get_scan_type_number(t_env *env);
char *get_scan_result_str(char *type, enum e_port_status result);
char *get_scan_conclusion(t_env *env, t_port_result *result);
int port_status_opened(t_env *env, t_port_result *result);
char *get_service_name(int port);
void debug_tcp_packet(t_tcp_packet *packet);
void debug_udp_packet(t_udp_packet *packet);
void debug_icmp_packet(t_icmp_packet *packet);
int16_t udp_checksum(t_udp_packet *packet, int pton_addr);
void scan_port_udp(t_thread_arg *thread_arg, struct iphdr *ip_header, int port);
void packet_flush_tcp(t_host *host, int port);
void packet_flush_icmp(t_host *host, int port);
t_tcp_packet *packet_get_tcp(t_host *host, int port, uint32_t sequence, char *type);
void *port_listener(void *data);
void packet_push_tcp(t_host *host, t_tcp_packet *packet);
void packet_push_icmp(t_host *host, t_icmp_packet *packet);
int packet_get_icmp(t_host *host, int port);
void resolve_self_ip(t_env *env);
void reserve_port(t_env *env);

#endif
