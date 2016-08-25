#include "ft_nmap.h"

void print_help(void)
{
	ft_putendl_fd("ft_nmap [--help] [--port ports] [--speedup speedups] [--scan scans] --ip x.x.x.x", 2);
	ft_putendl_fd("ft_nmap [--help] [--port ports] [--speedup speedups] [--scan scans] --file ip_file", 2);
	ft_putendl_fd("--help\t\tprint this help screen", 2);
	ft_putendl_fd("--ports\t\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15). Max is 1024 ports. Default is 1-1024", 2);
	ft_putendl_fd("--ip\t\tip addresses to scan in dot format", 2);
	ft_putendl_fd("--file\t\tfile name containing IP addresses to scan. One ip per line", 2);
	ft_putendl_fd("--speedup\t[250 max] number of parallel threads to use. Default is 1", 2);
	ft_putendl_fd("--scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP (eg: SYN,UDP or SYN). Default is everything", 2);
	exit(EXIT_FAILURE);
}
