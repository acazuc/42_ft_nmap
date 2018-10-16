#include "ft_nmap.h"

unsigned int rnd;

unsigned int lcrandom()
{
	return (rnd  = rnd * 1664525 + 1013904223);
}
