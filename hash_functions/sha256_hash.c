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
(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
*/
static const uint32_t K[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
Initialize hash values:
(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
h0 := 0x6a09e667
h1 := 0xbb67ae85
h2 := 0x3c6ef372
h3 := 0xa54ff53a
h4 := 0x510e527f
h5 := 0x9b05688c
h6 := 0x1f83d9ab
h7 := 0x5be0cd19
*/
static const struct sha256_state init_state = {
    .h0 = 0x6a09e667,
    .h1 = 0xbb67ae85,
    .h2 = 0x3c6ef372,
    .h3 = 0xa54ff53a,
    .h4 = 0x510e527f,
    .h5 = 0x9b05688c,
    .h6 = 0x1f83d9ab,
    .h7 = 0x5be0cd19,
};

static void sha256_hash_init(struct hash_context *ctx)
{
    struct sha256_state *state = (struct sha256_state *)ctx->state;
    
    *state = init_state;
}

/*
create a 64-entry message schedule array w[0..63] of 32-bit words
(The initial values in w[0..63] don't matter, so many implementations zero them here)
copy chunk into first 16 words w[0..15] of the message schedule array

Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
for i from 16 to 63
    s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
    s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    w[i] := w[i-16] + s0 + w[i-7] + s1
*/
static void message_schedule(uint32_t w[64], const uint8_t block[64])
{
    for (size_t i = 0; i < 16; i++)
    {
        size_t j = i * 4;
        /* the << 24 byte is cast: a uint8_t promotes to int, so any value
        ** >= 0x80 shifted left 24 would overflow a signed int (UB) */
        w[i] = block[j + 3] | block[j + 2] << 8 | block[j + 1] << 16
               | (uint32_t)block[j] << 24;
    }

    for (size_t i = 16; i < 64; i++)
    {
        uint32_t s0 = rightrotate(w[i-15], 7, 32) ^ rightrotate(w[i-15], 18, 32) ^ (w[i-15] >> 3);
        uint32_t s1 = rightrotate(w[i-2], 17, 32) ^ rightrotate(w[i-2],  19, 32) ^ (w[i-2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

void sha256_hash_process(struct hash_context *ctx, const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    message_schedule(w, block);

    struct sha256_state *state_ptr = (struct sha256_state*)ctx->state;
    uint32_t a = state_ptr->h0;
    uint32_t b = state_ptr->h1;
    uint32_t c = state_ptr->h2;
    uint32_t d = state_ptr->h3;
    uint32_t e = state_ptr->h4;
    uint32_t f = state_ptr->h5;
    uint32_t g = state_ptr->h6;
    uint32_t h = state_ptr->h7;

    for (size_t i = 0; i < 64; i++)
    {
        uint32_t S1, S0, temp1, temp2;

        S1 = rightrotate(e, 6, 32) ^ rightrotate(e, 11, 32) ^ rightrotate(e, 25, 32);
        temp1 = h + S1 + Ch(e, f, g) + K[i] + w[i];

        S0 = rightrotate(a, 2, 32) ^ rightrotate(a, 13, 32) ^ rightrotate(a, 22, 32);
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

void sha256_padding_buffer(struct hash_context *ctx)
{
        size_t buffer_len = ctx->buffer_len;

    uint8_t *buffer = ctx->buffer;

    buffer[buffer_len] = 0x80; // Append the '1' bit
    buffer_len++;

    if (buffer_len > SHA256_BLOCK_SIZE - 8)
    {
        memset(buffer + buffer_len, 0, SHA256_BLOCK_SIZE - buffer_len);
        sha256_hash_process(ctx, buffer);
        buffer_len = 0; // Reset buffer length after processing
    }
    memset(buffer + buffer_len, 0, SHA256_BLOCK_SIZE - 8 - buffer_len);
    buffer_len = SHA256_BLOCK_SIZE - 8;

    size_t total_len_bits = ctx->total_len * 8;
    big_endian_encode(total_len_bits, buffer + buffer_len, 8);
    sha256_hash_process(ctx, buffer);
}

static void sha256_hash_final(struct hash_context *ctx, uint8_t *output)
{
    sha256_padding_buffer(ctx);
    
    struct sha256_state *state = (struct sha256_state *)ctx->state;
    big_endian_encode(state->h0, output + 0, 4);
    big_endian_encode(state->h1, output + 4, 4);
    big_endian_encode(state->h2, output + 8, 4);
    big_endian_encode(state->h3, output + 12, 4);
    big_endian_encode(state->h4, output + 16, 4);
    big_endian_encode(state->h5, output + 20, 4);
    big_endian_encode(state->h6, output + 24, 4);
    big_endian_encode(state->h7, output + 28, 4);
}

const struct hash_function sha256_hash_function = {
    .base.name          = "sha256",
    .base.display_name  = "SHA256",
    .init               = sha256_hash_init,
    .process            = sha256_hash_process,
    .final              = sha256_hash_final,
    .state_size         = sizeof(struct sha256_state),
    .block_size         = SHA256_BLOCK_SIZE,
    .output_size        = SHA256_HASH_SIZE
};
