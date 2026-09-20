#ifndef CIPHER_FUNCTIONS_H
#define CIPHER_FUNCTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "ssl_function.h"

struct cipher_context
{
    void    *state;
    uint8_t *key;

    size_t  total_len;
    uint8_t *buffer;
    size_t  buffer_len;
};

struct cipher_function
{
    struct ssl_function func;
    int need_passphrase;

    void (*init)(struct cipher_context *ctx);
    void (*decrypt)(struct cipher_context *ctx, const uint8_t *cipher, uint8_t *plain);
    void (*encrypt)(struct cipher_context *ctx, const uint8_t *plain, uint8_t *cipher);
    
    size_t state_size;
    size_t block_size;
};

struct cipher_function *get_cipher_function_by_name(const char *name);
const struct cipher_function **get_cipher_function_list(void);

int run_cipher(struct cipher_function *cipher_func, const char *command, int argc,
               char **argv);

#endif /* CIPHER_FUNCTIONS_H */
