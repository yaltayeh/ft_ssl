#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "../ssl_function.h"

struct hash_context
{
    void    *state;

    size_t  total_len;
    uint8_t *buffer;
    size_t  buffer_len;
};

struct hash_function
{
    struct ssl_function base;
    void (*init)(struct hash_context *ctx);
    void (*process)(struct hash_context *ctx, const uint8_t *block);
    void (*final)(struct hash_context *ctx, uint8_t *output);
    size_t state_size;
    size_t block_size;
    uint8_t output_size;
};

struct flags
{
    int p;
    int q;
    int r;
};

int run_hash(const struct ssl_function *func,
				int optc,
				char **optv);

#endif /* HASH_FUNCTIONS_H */
