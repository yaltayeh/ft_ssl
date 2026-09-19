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

void sha256_hash_process(struct hash_context *ctx, const uint8_t block[SHA256_BLOCK_SIZE]);
void sha256_padding_buffer(struct hash_context *ctx);

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

void sha512_hash_process(struct hash_context *ctx, const uint8_t block[SHA512_BLOCK_SIZE]);
void sha512_padding_buffer(struct hash_context *ctx);

#endif // SHA_H
