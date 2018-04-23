#include "ft_nmap.h"

unsigned int lcrandom()
{
	static volatile unsigned int rnd = 0;
	
	if (!rnd)
		rnd = epoch_micro();
	return (rnd = rnd * 48271);
}
