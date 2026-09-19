#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_HASH_SIZE 32
#define SHA256_BLOCK_SIZE 64

#define SHA224_HASH_SIZE 28
#define SHA384_HASH_SIZE 48

#define SHA512_HASH_SIZE 64
#define SHA512_BLOCK_SIZE 128

struct sha256_state
{
    uint32_t h0;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
    uint32_t h5;
    uint32_t h6;
    uint32_t h7;
};

struct sha256_context
{
    struct sha256_state state;
    size_t total_len;
    uint8_t buffer[SHA256_BLOCK_SIZE];
    size_t buffer_len;
};

void sha256_hash_update(void *ctx, const uint8_t *data, size_t len);
void sha256_padding_buffer(struct sha256_context *sha256_ctx);

struct sha512_state
{
    uint64_t h0;
    uint64_t h1;
    uint64_t h2;
    uint64_t h3;
    uint64_t h4;
    uint64_t h5;
    uint64_t h6;
    uint64_t h7;
};

struct sha512_context
{
    struct sha512_state state;
    size_t total_len;
    uint8_t buffer[SHA512_BLOCK_SIZE];
    size_t buffer_len;
};

void sha512_hash_update(void *ctx, const uint8_t *data, size_t len);
void sha512_padding_buffer(struct sha512_context *sha256_ctx);

#endif // SHA_H
