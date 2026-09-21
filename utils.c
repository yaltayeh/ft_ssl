#include "ft_ssl.h"

// uint64_t rightrotate(uint64_t)

uint64_t permutation(uint64_t input, const uint8_t *table,
                             size_t table_size, size_t input_bit_width)
{
    uint64_t result = 0;

    for (size_t i = 0; i < table_size; i++)
    {
        size_t bit_position = input_bit_width - table[i];
        uint64_t bit = (input >> bit_position) & 1;
        result = (result << 1) | bit;
    }
    return result;
}

uint64_t rightrotate(uint64_t val, size_t n, size_t size)
{
    uint64_t mask;

    if (size >= 64)
        mask = ~0ULL;
    else
        mask = (1ULL << size) - 1;

    val &= mask;
    n %= size;
    if (n == 0)
        return (val);

    return ((val >> n) | (val << (size - n))) & mask;
}

uint64_t leftrotate(uint64_t val, size_t n, size_t size)
{
    uint64_t mask;

    if (size >= 64)
        mask = ~0ULL;
    else
        mask = (1ULL << size) - 1;

    val &= mask;
    n %= size;
    if (n == 0)
        return (val);

    return ((val << n) | (val >> (size - n))) & mask;
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
