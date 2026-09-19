#include "hash_functions.h"
#include "../ft_ssl.h"
#include "sha.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/*
SHA-224 initial hash values (in big endian):
(The second 32 bits of the fractional parts of the square roots of the 9th through 16th primes 23..53)
*/
static const struct sha256_state init_state = {
    .h0 = 0xc1059ed8,
    .h1 = 0x367cd507,
    .h2 = 0x3070dd17,
    .h3 = 0xf70e5939,
    .h4 = 0xffc00b31,
    .h5 = 0x68581511,
    .h6 = 0x64f98fa7,
    .h7 = 0xbefa4fa4,
};

static void sha224_hash_init(void *ctx)
{
    struct sha256_context *sha224_ctx = (struct sha256_context *)ctx;

    sha224_ctx->state = init_state;
    sha224_ctx->total_len = 0;
    sha224_ctx->buffer_len = 0;
}

static void sha224_hash_final(void *ctx, uint8_t *output)
{
    struct sha256_context *sha224_ctx = (struct sha256_context *)ctx;

    sha256_padding_buffer(sha224_ctx);

    big_endian_encode(sha224_ctx->state.h0, output + 0, 4);
    big_endian_encode(sha224_ctx->state.h1, output + 4, 4);
    big_endian_encode(sha224_ctx->state.h2, output + 8, 4);
    big_endian_encode(sha224_ctx->state.h3, output + 12, 4);
    big_endian_encode(sha224_ctx->state.h4, output + 16, 4);
    big_endian_encode(sha224_ctx->state.h5, output + 20, 4);
    big_endian_encode(sha224_ctx->state.h6, output + 24, 4);
}

const struct hash_function sha224_hash_function = {
    "sha224",
    "SHA224",
    sha224_hash_init,
    sha256_hash_update,
    sha224_hash_final,
    sizeof(struct sha256_context),
    SHA256_BLOCK_SIZE,
    SHA224_HASH_SIZE
};
