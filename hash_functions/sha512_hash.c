#include "hash_functions.h"
#include "../ft_ssl.h"
#include "sha.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/*
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380

Pre-processing (Padding):
begin with the original message of length L bits
append a single '1' bit
append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
such that the bits in the message are: ⟨original message of length L⟩ 1 ⟨K zeros⟩ ⟨L as 64 bit integer⟩ , (the number of bits will be a multiple of 512)


Produce the final hash value (big-endian):
digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
*/

// Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)
#define Ch(e, f, g) ((e & f) | (~e & g))

// Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
#define Maj(a, b, c) ((a & b) | (a & c) | (b & c))

/*
Initialize array of round constants:
(first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
*/
static const uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/*
Initialize hash values:
(first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19):
0x6a09e667f3bcc908,
0xbb67ae8584caa73b,
0x3c6ef372fe94f82b,
0xa54ff53a5f1d36f1, 
0x510e527fade682d1,
0x9b05688c2b3e6c1f,
0x1f83d9abfb41bd6b,
0x5be0cd19137e2179
*/
static const struct sha512_state init_state = {
    .h0 = 0x6a09e667f3bcc908,
    .h1 = 0xbb67ae8584caa73b,
    .h2 = 0x3c6ef372fe94f82b,
    .h3 = 0xa54ff53a5f1d36f1,
    .h4 = 0x510e527fade682d1,
    .h5 = 0x9b05688c2b3e6c1f,
    .h6 = 0x1f83d9abfb41bd6b,
    .h7 = 0x5be0cd19137e2179,
};

static void sha512_hash_init(struct hash_context *ctx)
{
    struct sha512_state *state = (struct sha512_state *)ctx->state;
    
    *state = init_state;
}

/*
create a 64-entry message schedule array w[0..63] of 32-bit words
(The initial values in w[0..63] don't matter, so many implementations zero them here)
copy chunk into first 16 words w[0..15] of the message schedule array

Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
for i from 16 to 63
	SHA-512 Sum & Sigma:
	s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
	s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
    w[i] := w[i-16] + s0 + w[i-7] + s1
*/
static void message_schedule(uint64_t w[80], const uint8_t block[SHA512_BLOCK_SIZE])
{
    for (size_t i = 0; i < 16; i++)
    {
        size_t j = i * 8;
        w[i] = ((uint64_t)block[j]  << 56) | ((uint64_t)block[j + 1] << 48) |
            ((uint64_t)block[j + 2] << 40) | ((uint64_t)block[j + 3] << 32) |
            ((uint64_t)block[j + 4] << 24) | ((uint64_t)block[j + 5] << 16) |
            ((uint64_t)block[j + 6] << 8)  | ((uint64_t)block[j + 7]);
    }

    for (size_t i = 16; i < 80; i++)
    {
        uint64_t s0 = rightrotate_64(w[i-15], 1) ^ rightrotate_64(w[i-15], 8) ^ (w[i-15] >> 7);
        uint64_t s1 = rightrotate_64(w[i-2], 19) ^ rightrotate_64(w[i-2],  61) ^ (w[i-2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

void sha512_hash_process(struct hash_context *ctx, const uint8_t block[SHA512_BLOCK_SIZE])
{
    uint64_t w[80];
    message_schedule(w, block);

    struct sha512_state *state_ptr = (struct sha512_state*)ctx->state;
    uint64_t a = state_ptr->h0;
    uint64_t b = state_ptr->h1;
    uint64_t c = state_ptr->h2;
    uint64_t d = state_ptr->h3;
    uint64_t e = state_ptr->h4;
    uint64_t f = state_ptr->h5;
    uint64_t g = state_ptr->h6;
    uint64_t h = state_ptr->h7;

    for (size_t i = 0; i < 80; i++)
    {
        uint64_t S1, S0, temp1, temp2;

        S1 = rightrotate_64(e, 14) ^ rightrotate_64(e, 18) ^ rightrotate_64(e, 41);
        temp1 = h + S1 + Ch(e, f, g) + K[i] + w[i];

        S0 = rightrotate_64(a, 28) ^ rightrotate_64(a, 34) ^ rightrotate_64(a, 39);
        temp2 = S0 + Maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_ptr->h0 += a;
    state_ptr->h1 += b;
    state_ptr->h2 += c;
    state_ptr->h3 += d;
    state_ptr->h4 += e;
    state_ptr->h5 += f;
    state_ptr->h6 += g;
    state_ptr->h7 += h;
}

void sha512_padding_buffer(struct hash_context *ctx)
{
    size_t buffer_len = ctx->buffer_len;

    uint8_t *buffer = ctx->buffer;

    buffer[buffer_len] = 0x80; // Append the '1' bit
    buffer_len++;

    if (buffer_len > SHA512_BLOCK_SIZE - 16)
    {
        memset(buffer + buffer_len, 0, SHA512_BLOCK_SIZE - buffer_len);
        sha512_hash_process(ctx, buffer);
        buffer_len = 0; // Reset buffer length after processing
    }
    memset(buffer + buffer_len, 0, SHA512_BLOCK_SIZE - 16 - buffer_len);
    buffer_len = SHA512_BLOCK_SIZE - 16;

    size_t total_len_bits = ctx->total_len * 8;
    memset(buffer + buffer_len, 0, 8);
    big_endian_encode(total_len_bits, buffer + buffer_len + 8, 8);
    sha512_hash_process(ctx, buffer);
}

static void sha512_hash_final(struct hash_context *ctx, uint8_t *output)
{
    sha512_padding_buffer(ctx);

    struct sha512_state *state = (struct sha512_state *)ctx->state;
    big_endian_encode(state->h0, output + 0,  8);
    big_endian_encode(state->h1, output + 8,  8);
    big_endian_encode(state->h2, output + 16, 8);
    big_endian_encode(state->h3, output + 24, 8);
    big_endian_encode(state->h4, output + 32, 8);
    big_endian_encode(state->h5, output + 40, 8);
    big_endian_encode(state->h6, output + 48, 8);
    big_endian_encode(state->h7, output + 56, 8);
}

const struct hash_function sha512_hash_function = {
    .func.name          = "sha512",
    .func.display_name  = "SHA512",
    .init               = sha512_hash_init,
    .process            = sha512_hash_process,
    .final              = sha512_hash_final,
    .state_size         = sizeof(struct sha512_state),
    .block_size         = SHA512_BLOCK_SIZE,
    .output_size        = SHA512_HASH_SIZE
};
