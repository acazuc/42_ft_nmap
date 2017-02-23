#include "ft_nmap.h"

void print_help(void)
{
	fprintf
	(
		stderr,
		SKY "ft_nmap" WHITE " [" PINK "--help"
		WHITE "] [" BLUE "--port ports" WHITE "] [" RED "--speedup speedups"
		WHITE "] [" PEACHY "--scan scans" WHITE "] " GREEN "--ip x.x.x.x\n" WHITE

		SKY "ft_nmap" WHITE " [" PINK "--help"
		WHITE "] [" BLUE "--port ports" WHITE "] [" RED "--speedup speedups"
		WHITE "] [" PEACHY "--scan scans" WHITE "] " YELLOW "--file ip_file\n" WHITE

		PINK "--help" WHITE "\t\tprint this help screen\n"
		BLUE "--ports" WHITE "\t\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15). Max is 1024 ports. Default is 1-1024\n"
		GREEN "--ip" WHITE "\t\tip addresses to scan in dot format\n"
		YELLOW "--file" WHITE "\t\tfile name containing IP addresses to scan. One ip per line\n"
		RED "--speedup" WHITE "\t[250 max] number of parallel threads to use. Default is 1\n"
		PEACHY "--scan" WHITE "\t\tSYN/NULL/FIN/XMAS/ACK/UDP (eg: SYN,UDP or SYN). Default is everything\n"
	);
	exit(EXIT_FAILURE);
}
