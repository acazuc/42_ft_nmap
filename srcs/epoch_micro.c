#include "ft_nmap.h"

size_t epoch_micro(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL))
	{
		ft_putendl_fd("ft_nmap: can't get time", 2);
		exit(EXIT_FAILURE);
	}
	return (tv.tv_sec * 1000000 + tv.tv_usec);
}
