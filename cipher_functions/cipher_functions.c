#include "cipher_functions.h"
#include <string.h>

static const struct cipher_function *cipher_functions[] = {
    NULL
};

const struct cipher_function **get_cipher_function_list(void)
{
    return (const struct cipher_function **)cipher_functions;
}

struct cipher_function *get_cipher_function_by_name(const char *name)
{
    for (size_t i = 0; cipher_functions[i] != NULL; i++)
    {
        if (strcmp(cipher_functions[i]->name, name) == 0)
            return (struct cipher_function *)cipher_functions[i];
    }
    return NULL;
}
