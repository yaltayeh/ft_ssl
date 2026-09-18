#include "ft_ssl.h"

uint32_t rightrotate(uint32_t val, int n)
{
	if (n % 32 == 0)
		return (val); 
	return ((val >> n) | (val << (32 - n))); 
}

uint32_t leftrotate(uint32_t val, int n)
{
    if (n % 32 == 0)
        return (val);
    return ((val << n) | (val >> (32 - n)));
}

void little_endian_encode(uint64_t value, uint8_t *output, size_t output_size)
{
    for (size_t i = 0; i < output_size; i++)
    {
        output[i] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
}

void big_endian_encode(uint64_t value, uint8_t *output, size_t output_size)
{
    for (size_t i = 0; i < output_size; i++)
    {
        output[output_size - 1 - i] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
}
