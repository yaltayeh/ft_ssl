#ifndef CRYPTION_FUNCTIONS_H
#define CRYPTION_FUNCTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "../ssl_function.h"

struct cryption_context
{
    void        *state;
};

struct cryption_function
{
    struct ssl_function func;

    void (*init)(struct cryption_context *ctx, const uint8_t *raw_key);
    void (*decrypt)(struct cryption_context *ctx, const uint8_t *cipher, uint8_t *plain);
    void (*encrypt)(struct cryption_context *ctx, const uint8_t *plain, uint8_t *cipher);
    
    size_t key_size;
    size_t state_size;
    size_t block_size;
    int    needs_iv;
};

// enum modes
// {
//     MODE_ENCRYPTION,
//     MODE_DECRYPTION
// };

// struct flags
// {
//     enum modes mode;
//     char *input;
//     char *output;
// };

int run_cryption(const struct ssl_function *func,
                int optc,
                char **optv);

#endif /* CRYPTION_FUNCTIONS_H */
