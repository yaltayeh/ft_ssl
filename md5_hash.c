#include "ft_ssl.h"
#include <unistd.h>
#include <stdio.h>

#define MD5_HASH_SIZE 16
#define BLOCK_SIZE 64

struct md5_context
{
    
};

void md5_hash_init(void *ctx)
{
    struct md5_context *md5_ctx = (struct md5_context *)ctx;
    (void)md5_ctx;
}

void md5_hash_update(void *ctx, const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;

    struct md5_context *md5_ctx = (struct md5_context *)ctx;
    (void)md5_ctx;
}

void md5_hash_final(void *ctx, uint8_t *output)
{
    struct md5_context *md5_ctx = (struct md5_context *)ctx;
    (void)md5_ctx;
    (void)output;
}

const struct hash_function md5_hash_function = {
    "md5",
    md5_hash_init,
    md5_hash_update,
    md5_hash_final,
    sizeof(struct md5_context),
    BLOCK_SIZE,
    MD5_HASH_SIZE
};
