#include "hash_functions.h"
#include "../ft_ssl.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define MD5_HASH_SIZE 16
#define BLOCK_SIZE 64

// F is Conditional Selection the b is the selector, if b is 1 then c is selected else d is selected
#define F(b, c, d) ((b & c) | (~b & d))

// G is Conditional Selection the d is the selector, if d is 1 then b is selected else c is selected
#define G(b, c, d) ((b & d) | (c & ~d))

// H is Parity Function
#define H(b, c, d) (b ^ c ^ d)

// I is non pattern function
#define I(b, c, d) (c ^ (b | ~d))

struct md5_state
{
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
};

/*
for i from 0 to 63 do
    K[i] := floor(232 × abs(sin(i + 1)))
end for
*/
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t g[64] = {
    /* round 1 (F): g(i) = i */
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    /* round 2 (G): g(i) = (5i + 1) mod 16 */
     1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
    /* round 3 (H): g(i) = (3i + 5) mod 16 */
     5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
    /* round 4 (I): g(i) = (7i) mod 16 */
     0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
};

static const uint8_t S[64] = {
    /* round 1 */
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    /* round 2 */
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    /* round 3 */
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    /* round 4 */
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

/*
A = 67 45 23 01
B = ef cd ab 89
C = 98 ba dc fe
D = 10 32 54 76

little-endian for:
01 23 45 67 // correct order
89 ab cd ef
fe dc ba 98 // reverse order
76 54 32 10
*/
static const struct md5_state init_state = {
    .A = 0x67452301,
    .B = 0xefcdab89,
    .C = 0x98badcfe,
    .D = 0x10325476
};

static void md5_init(struct hash_context *ctx)
{
    struct md5_state *state = (struct md5_state *)ctx->state;
    
    *state = init_state;
}

static uint32_t FGHI(size_t i, uint32_t b, uint32_t c, uint32_t d)
{
    switch (i % 4)
    {
    case 0:
        return (F(b, c, d));
    case 1:
        return (G(b, c, d));
    case 2:
        return (H(b, c, d));
    case 3:
        return (I(b, c, d));
    default:
        return (0);
    }
}

static void md5_process_block(struct hash_context *ctx, const uint8_t block[BLOCK_SIZE])
{
    // copy the current state to local variables
    struct md5_state *state_ptr = (struct md5_state*)ctx->state;
    struct md5_state state = *state_ptr;

    // Process the block (this is a placeholder, actual MD5 processing logic should be implemented here)

    uint32_t M[16];

    for (size_t i = 0; i < sizeof(M) / sizeof(M[0]); i++)
    {
        size_t j = i * 4;
        /* the << 24 byte is cast: a uint8_t promotes to int, so any value
        ** >= 0x80 shifted left 24 would overflow a signed int (UB) */
        M[i] = block[j] | block[j + 1] << 8 | block[j + 2] << 16
               | (uint32_t)block[j + 3] << 24;
    }

    for (size_t i = 0; i < 64; i++)
    {
        size_t round = i / 16;
        uint32_t res = FGHI(round, state.B, state.C, state.D);
        res += state.A + K[i] + M[g[i]];
        state.A = state.D;
        state.D = state.C;
        state.C = state.B;
        state.B = state.B + leftrotate_32(res, S[i]);
    }

    // Update the state with the processed values
    state_ptr->A += state.A;
    state_ptr->B += state.B;
    state_ptr->C += state.C;
    state_ptr->D += state.D;
}

static void padding_buffer(struct hash_context *ctx)
{
    size_t buffer_len = ctx->buffer_len;

    uint8_t *buffer = ctx->buffer;

    buffer[buffer_len] = 0x80; // Append the '1' bit
    buffer_len++;

    if (buffer_len > BLOCK_SIZE - 8)
    {
        memset(buffer + buffer_len, 0, BLOCK_SIZE - buffer_len);
        md5_process_block(ctx, buffer);
        buffer_len = 0; // Reset buffer length after processing
    }
    memset(buffer + buffer_len, 0, BLOCK_SIZE - 8 - buffer_len);
    buffer_len = BLOCK_SIZE - 8;

    size_t total_len_bits = ctx->total_len * 8;
    little_endian_encode(total_len_bits, buffer + buffer_len, 8);
    md5_process_block(ctx, buffer);
}

static void md5_final(struct hash_context *ctx, uint8_t *output)
{    
    padding_buffer(ctx);
    
    struct md5_state *state = (struct md5_state *)ctx->state;
    little_endian_encode(state->A, output + 0, 4);
    little_endian_encode(state->B, output + 4, 4);
    little_endian_encode(state->C, output + 8, 4);
    little_endian_encode(state->D, output + 12, 4);
}

const struct hash_function md5_hash_function = {
    "md5",
    "MD5",
    md5_init,
    md5_process_block,
    md5_final,
    sizeof(struct md5_state),
    BLOCK_SIZE,
    MD5_HASH_SIZE
};
