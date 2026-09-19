#include "hash_functions.h"
#include "../ft_ssl.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 64
#define HASH_SIZE 16

struct whirlpool_context
{
	uint8_t buffer[64];
    size_t buffer_len;
    uint64_t total_len;
};

static void whirlpool_hash_init(void *ctx)
{
    struct whirlpool_context *w_ctx = (struct whirlpool_context *)ctx;
	(void)w_ctx;
}

static void process_whirlpool_block(struct whirlpool_context *w_ctx, const uint8_t block[BLOCK_SIZE])
{
	(void)w_ctx;
	(void)block;
}

static void whirlpool_hash_update(void *ctx, const uint8_t *data, size_t len)
{
    struct whirlpool_context *w_ctx = (struct whirlpool_context *)ctx;
    w_ctx->total_len += len;

    if (w_ctx->buffer_len > 0)
    {
        size_t space_in_buffer = BLOCK_SIZE - w_ctx->buffer_len;
        size_t to_copy = (len < space_in_buffer) ? len : space_in_buffer;
        memcpy(w_ctx->buffer + w_ctx->buffer_len, data, to_copy);
        w_ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if (w_ctx->buffer_len == BLOCK_SIZE)
        {
            process_whirlpool_block(w_ctx, w_ctx->buffer);
            w_ctx->buffer_len = 0; // Reset buffer length after processing
        }
    }
    while (len >= BLOCK_SIZE)
    {
        process_whirlpool_block(w_ctx, data);
        data += BLOCK_SIZE;
        len -= BLOCK_SIZE; // Simulate processing a block
    }
    if (len > 0)
    {
        // Store remaining data in the buffer
        memcpy(w_ctx->buffer, data, len);
        w_ctx->buffer_len = len;
    }
}

static void whirlpool_hash_final(void *ctx, uint8_t *output)
{
    struct whirlpool_context *w_ctx = (struct whirlpool_context *)ctx;
    (void)w_ctx;
}

const struct hash_function whirlpool_hash_function = {
    "whirlpool",
    "WHIRLPOOL",
    whirlpool_hash_init,
    whirlpool_hash_update,
    whirlpool_hash_final,
    sizeof(struct whirlpool_context),
    BLOCK_SIZE,
    HASH_SIZE
};
