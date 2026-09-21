#include "cryption_functions.h"
#include <string.h>
#include "../ft_ssl.h"

#define BLOCK_SIZE 8
#define KEY_SIZE 8

struct des_state
{
	uint64_t subkeys[16];
};

static const uint8_t PC1[] = {
	57, 49, 41, 33, 25, 17, 9,
	1,  58, 50, 42, 34, 26, 18,
	10, 2,  59, 51, 43, 35, 27,
	19, 11, 3,  60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7,  62, 54, 46, 38, 30, 22,
	14, 6,  61, 53, 45, 37, 29,
	21, 13, 5,  28, 20, 12, 4
};
static const size_t PC1_size = sizeof(PC1) / sizeof(PC1[0]);

static const uint8_t PC2[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};
static const size_t PC2_size = sizeof(PC2) / sizeof(PC2[0]);

static const uint8_t E[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};
static const size_t E_size = sizeof(E) / sizeof(E[0]);

static const uint8_t P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};
static const size_t P_size = sizeof(P) / sizeof(P[0]);

static const uint8_t IP[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};
static const size_t IP_size = sizeof(IP) / sizeof(IP[0]);

static const uint8_t FP[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};
static const size_t FP_size = sizeof(FP) / sizeof(FP[0]);

static const uint8_t KEY_SHIFT[] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

static const uint8_t S_BOX[8][4][16] = {
    // S1
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    // S2
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    // S3
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    // S4
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    // S5
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    // S6
    {
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    // S7
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    // S8
    {
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

static uint32_t substitution(uint64_t input48)
{
    uint32_t output = 0;

    for (int i = 0; i < 8; i++)
    {
        int shift = 48 - (i + 1) * 6;
        uint8_t chunk = (input48 >> shift) & 0x3F;

        uint8_t row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        uint8_t col = (chunk >> 1) & 0x0F;

        uint8_t value = S_BOX[i][row][col];

        output = (output << 4) | value;
    }
    return output;
}

static void key_schedule(uint64_t key64, uint64_t subkeys[16])
{
    uint64_t key56 = permutation(key64, PC1, PC1_size, 64);

    uint32_t C = (key56 >> 28) & 0x0FFFFFFF;
    uint32_t D = key56 & 0x0FFFFFFF;

    for (int i = 0; i < 16; i++)
    {
        C = (uint32_t)leftrotate(C, KEY_SHIFT[i], 28);
        D = (uint32_t)leftrotate(D, KEY_SHIFT[i], 28);

        uint64_t concat = ((uint64_t)C << 28) | D;
        subkeys[i] = permutation(concat, PC2, PC2_size, 56);
    }
}

static uint32_t feistel_f(uint32_t right, uint64_t subkey)
{
    uint64_t expanded = permutation(right, E, E_size, 32);   // 32 → 48 بت
    expanded ^= subkey;                                       // XOR مع subkey الجولة
    uint32_t substituted = substitution(expanded);            // 48 → 32 بت
    uint32_t result = (uint32_t)permutation(substituted, P, P_size, 32);  // 32 → 32 بت

    return result;
}

static void des_init(struct cryption_context *ctx, const uint8_t *raw_key)
{
	struct des_state *state = ctx->state;

	uint64_t key;

	key = big_endian_decode(raw_key, KEY_SIZE);
	key_schedule(key, state->subkeys);
    memset(&key, 0, sizeof(key));
}

static uint64_t des_process_block(uint64_t block, const uint64_t subkeys[16], int decrypt)
{
    uint64_t permuted = permutation(block, IP, IP_size, 64);

    uint32_t left  = (uint32_t)(permuted >> 32);
    uint32_t right = (uint32_t)(permuted & 0xFFFFFFFF);

    for (int round = 0; round < 16; round++)
    {
        int key_index = decrypt ? (15 - round) : round;

        uint32_t tmp = right;
        right = left ^ feistel_f(right, subkeys[key_index]);
        left = tmp;
    }

    uint64_t combined = ((uint64_t)right << 32) | left;   // لاحظ: right أولاً!

    uint64_t result = permutation(combined, FP, FP_size, 64);

    return result;
}

static void des_encrypt(struct cryption_context *ctx, const uint8_t *plain, uint8_t *cipher)
{
    struct des_state *state = (struct des_state *)ctx->state;
	uint64_t plain_block;
	uint64_t cipher_block;


	plain_block = big_endian_decode(plain, BLOCK_SIZE);
	cipher_block = des_process_block(plain_block, state->subkeys, 0);
    big_endian_encode(cipher_block, cipher, BLOCK_SIZE);
}

static void des_decrypt(struct cryption_context *ctx, const uint8_t *cipher, uint8_t *plain)
{
    struct des_state *state = (struct des_state *)ctx->state;
    uint64_t cipher_block;
    uint64_t plain_block;
    
    cipher_block = big_endian_decode(cipher, BLOCK_SIZE);
    plain_block = des_process_block(cipher_block, state->subkeys, 1);
    big_endian_encode(plain_block, plain, BLOCK_SIZE);
}

const struct cryption_function des_ecb_cryption_function = {
    .func.name         = "des-ecb",
    .func.display_name = "DES-ECB",
    .init              = des_init,
    .encrypt           = des_encrypt,
    .decrypt           = des_decrypt,
    .key_size          = KEY_SIZE,
    .state_size        = sizeof(struct des_state),
    .block_size        = BLOCK_SIZE,
    .needs_iv          = 0,
};

const struct cryption_function des_cbc_cryption_function = {
    .func.name         = "des-cbc",
    .func.display_name = "DES-CBC",
    .init              = des_init,       // نفس init بالضبط!
    .encrypt           = des_encrypt,    // نفس encrypt بالضبط!
    .decrypt           = des_decrypt,    // نفس decrypt بالضبط!
    .key_size          = KEY_SIZE,
    .state_size        = sizeof(struct des_state),
    .block_size        = BLOCK_SIZE,
    .needs_iv          = 1,              // ← الفرق الوحيد!
};