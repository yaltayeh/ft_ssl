#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

const uint8_t PC1[] = {
	57, 49, 41, 33, 25, 17, 9,
	1,  58, 50, 42, 34, 26, 18,
	10, 2,  59, 51, 43, 35, 27,
	19, 11, 3,  60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7,  62, 54, 46, 38, 30, 22,
	14, 6,  61, 53, 45, 37, 29,
	21, 13, 5,  28, 20, 12, 4
};

static uint64_t permutation(uint64_t input, const uint8_t *table,
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

int main()
{
	uint64_t key64 = 0xFFFFFFFFFFFFFFFF;
	uint64_t key56 = permutation(key64, PC1, 56, 64);

	printf("%llx\n", key56);
}
