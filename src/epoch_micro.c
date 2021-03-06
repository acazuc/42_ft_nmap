#include "ft_nmap.h"

size_t epoch_micro(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL))
	{
		fprintf(stderr, RED "ft_nmap: can't get time\n" DEFAULT);
		exit(EXIT_FAILURE);
	}
	return (tv.tv_sec * 1000000 + tv.tv_usec);
}
