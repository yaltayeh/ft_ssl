#include "ft_ssl.h"
#include <unistd.h>
#include <stdio.h>

#define SHA256_HASH_SIZE 32
#define BLOCK_SIZE 64

struct sha256_context
{
    
};

void sha256_hash_init(void *ctx)
{
    struct sha256_context *sha256_ctx = (struct sha256_context *)ctx;
    (void)sha256_ctx;
}

void sha256_hash_update(void *ctx, const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;

    struct sha256_context *sha256_ctx = (struct sha256_context *)ctx;
    (void)sha256_ctx;
}

void sha256_hash_final(void *ctx, uint8_t *output)
{
    struct sha256_context *sha256_ctx = (struct sha256_context *)ctx;
    (void)sha256_ctx;
    (void)output;
}

const struct hash_function sha256_hash_function = {
    "sha256",
    sha256_hash_init,
    sha256_hash_update,
    sha256_hash_final,
    sizeof(struct sha256_context),
    BLOCK_SIZE,
    SHA256_HASH_SIZE
};
