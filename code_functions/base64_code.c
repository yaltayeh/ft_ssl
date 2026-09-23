#include "code_functions.h"
#include <string.h>
#include <stdlib.h>
#include "../ft_ssl.h"

static const char BASE64_ALPHABET[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const char ALPHABET_BASE64[] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7, 
    ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, 
    ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23, 
    ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, 
    ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
    ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, 
    ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
    ['='] = 0,
};

static void base64_encode(const uint8_t data[3], uint8_t codes[4])
{
    uint64_t block = big_endian_decode(data, 3);

    codes[0] = BASE64_ALPHABET[(block >> 18) & 0x3F];
    codes[1] = BASE64_ALPHABET[(block >> 12) & 0x3F];
    codes[2] = BASE64_ALPHABET[(block >> 6)  & 0x3F];
    codes[3] = BASE64_ALPHABET[ block        & 0x3F];
}

static int check_base64(char c)
{
    return ((c >= 'a' && c <= 'z')
         || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9')
         || c == '+' || c == '/' || c == '=');
}

static int base64_decode(const uint8_t codes[4], uint8_t data[3])
{
    uint64_t block = 0;

    for (size_t i = 0; i < 4; i++)
    {
        if (!check_base64(codes[i]))
            return (-1);
        block <<= 6;
        block |= ALPHABET_BASE64[codes[i]];
    }
    big_endian_encode(block, data, 3);

    return (0);
}

char *data_to_base64(const uint8_t *data, size_t size)
{
    size_t full_blocks = size / 3;
    size_t remainder   = size % 3;
    size_t out_size    = ((size + 2) / 3) * 4;

    char *out = malloc(out_size + 1);
    if (!out)
        return (NULL);

    for (size_t i = 0; i < full_blocks; i++)
        base64_encode(data + (i * 3), (uint8_t *)out + (i * 4));

    if (remainder > 0)
    {
        uint8_t last[3] = {0, 0, 0};
        memcpy(last, data + (full_blocks * 3), remainder);

        uint8_t *dst = (uint8_t *)out + (full_blocks * 4);
        base64_encode(last, dst);

        size_t valid_codes = (remainder * 8 + 5) / 6;
        for (size_t i = valid_codes; i < 4; i++)
            dst[i] = '=';
    }

    out[out_size] = '\0';
    return (out);
}

const struct code_function base64_function = {
    .base.name         = "base64",
    .base.display_name = "BASE64",
    .encode            = base64_encode,
    .decode            = base64_decode,
    .text_size         = 3,
    .codes_size        = 4, 
};
