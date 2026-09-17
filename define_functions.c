#include "ft_ssl.h"
#include <string.h>

extern const struct hash_function md5_hash_function;
extern const struct hash_function sha256_hash_function;

static const struct hash_function *hash_functions[] = {
    &md5_hash_function,
    &sha256_hash_function,
    NULL
};

struct hash_function *get_hash_function_by_name(const char *name)
{
    for (size_t i = 0; hash_functions[i] != NULL; i++)
    {
        if (strcmp(hash_functions[i]->name, name) == 0)
            return (struct hash_function *)hash_functions[i];
    }
    return NULL;
}
