#include "ft_ssl.h"

// uint64_t rightrotate(uint64_t)

#define rightrotate(bits)                                           \
    uint##bits##_t rightrotate_##bits(uint##bits##_t val, int n)    \
    {                                                               \
        if (n % bits == 0)                                          \
            return (val);                                           \
        return ((val >> n) | (val << (bits - n)));                  \
    }

rightrotate(32)
rightrotate(64)

#undef rightrotate

#define leftrotate(bits)                                        \
    uint##bits##_t leftrotate_##bits(uint##bits##_t val, int n) \
    {                                                           \
        if (n % bits == 0)                                      \
            return (val);                                       \
        return ((val << n) | (val >> (bits - n)));              \
    }

leftrotate(32)
leftrotate(64)

#undef leftrotate


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
