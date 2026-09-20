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

static void sha224_hash_init(struct hash_context *ctx)
{
    struct sha256_state *state = (struct sha256_state *)ctx->state;
    
    *state = init_state;
}

static void sha224_hash_final(struct hash_context *ctx, uint8_t *output)
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
}

const struct hash_function sha224_hash_function = {
    .func.name          = "sha224",
    .func.display_name  = "SHA224",
    .init               = sha224_hash_init,
    .process            = sha256_hash_process,
    .final              = sha224_hash_final,
    .state_size         = sizeof(struct sha256_state),
    .block_size         = SHA256_BLOCK_SIZE,
    .output_size        = SHA224_HASH_SIZE
};
