#include "ft_nmap.h"

uint16_t ip_checksum(void *addr, size_t len)
{
	uint64_t result;
	uint16_t *tmp;

	tmp = (uint16_t*)addr;
	result = 0;
	while (len > 1)
	{
		result += *(tmp++);
		len -= 2;
	}
	if (len)
		result += *((uint8_t*)tmp);
	while (result > 0xFFFF)
		result = ((result >> 16) & 0xFFFF) + (result & 0xFFFF);
	return (~((uint16_t)result));
}
