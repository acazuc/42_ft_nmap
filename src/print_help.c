#include "ft_nmap.h"

void print_help(void)
{
	fprintf(stderr, "ft_nmap [--help] [--port ports] [--speedup speedups] [--scan scans] --ip x.x.x.x\n"
	"ft_nmap [--help] [--port ports] [--speedup speedups] [--scan scans] --file ip_file\n"
	"--help\t\tprint this help screen\n"
	"--ports\t\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15). Max is 1024 ports. Default is 1-1024\n"
	"--ip\t\tip addresses to scan in dot format\n"
	"--file\t\tfile name containing IP addresses to scan. One ip per line\n"
	"--speedup\t[250 max] number of parallel threads to use. Default is 1\n"
	"--scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP (eg: SYN,UDP or SYN). Default is everything\n");
	exit(EXIT_FAILURE);
}
