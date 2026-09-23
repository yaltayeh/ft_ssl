#ifndef code_FUNCTIONS_H
#define code_FUNCTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "../ssl_function.h"

struct code_function
{
    struct ssl_function func;

    void (*encode)(const uint8_t *text, uint8_t *codes);
    int (*decode)(const uint8_t *codes, uint8_t *text);
    
    size_t text_size;
    size_t codes_size;
};

int run_code(const struct ssl_function *func,
                int optc,
                char **optv);

#endif /* code_FUNCTIONS_H */
