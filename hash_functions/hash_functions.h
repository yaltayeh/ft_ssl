#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H

#include <stdint.h>
#include <stddef.h>

struct hash_function
{
    const char *name;
    const char *display_name;
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*final)(void *ctx, uint8_t *output);
    size_t ctx_size;
    size_t block_size;
    uint8_t output_size;
};

struct flags
{
    int p;
    int q;
    int r;
};

struct hash_function *get_hash_function_by_name(const char *name);
const struct hash_function **get_hash_function_list(void);

int run_hash(struct hash_function *hash_func, const char *command, int argc,
             char **argv);

#endif /* HASH_FUNCTIONS_H */
