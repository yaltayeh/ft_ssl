#include "hash_functions.h"
#include "../ft_ssl.h"
#include "sha.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/*
Initialize hash values:
(first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19):
the initial hash values h0 through h7 are different (taken from the 9th through 16th primes), and
the output is constructed by omitting h6 and h7.

0xcbbb9d5dc1059ed8,
0x629a292a367cd507,
0x9159015a3070dd17,
0x152fecd8f70e5939, 
0x67332667ffc00b31,
0x8eb44a8768581511,
0xdb0c2e0d64f98fa7,
0x47b5481dbefa4fa4
*/
static const struct sha512_state init_state = {
    .h0 = 0xcbbb9d5dc1059ed8,
    .h1 = 0x629a292a367cd507,
    .h2 = 0x9159015a3070dd17,
    .h3 = 0x152fecd8f70e5939,
    .h4 = 0x67332667ffc00b31,
    .h5 = 0x8eb44a8768581511,
    .h6 = 0xdb0c2e0d64f98fa7,
    .h7 = 0x47b5481dbefa4fa4,
};

static void sha384_hash_init(struct hash_context *ctx)
{
    struct sha512_state *state = (struct sha512_state *)ctx->state;
    
    *state = init_state;
}

static void sha384_hash_final(struct hash_context *ctx, uint8_t *output)
{
    sha512_padding_buffer(ctx);

    struct sha512_state *state = (struct sha512_state *)ctx->state;
    big_endian_encode(state->h0, output + 0,  8);
    big_endian_encode(state->h1, output + 8,  8);
    big_endian_encode(state->h2, output + 16, 8);
    big_endian_encode(state->h3, output + 24, 8);
    big_endian_encode(state->h4, output + 32, 8);
    big_endian_encode(state->h5, output + 40, 8);
}

const struct hash_function sha384_hash_function = {
    .func.name          = "sha384",
    .func.display_name  = "SHA384",
    .init               = sha384_hash_init,
    .process            = sha512_hash_process,
    .final              = sha384_hash_final,
    .state_size         = sizeof(struct sha512_state),
    .block_size         = SHA512_BLOCK_SIZE,
    .output_size        = SHA384_HASH_SIZE
};
