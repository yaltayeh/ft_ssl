#include "ssl_function.h"
#include <stddef.h>
#include <string.h>

extern const struct ssl_functions_group hash_group;
extern const struct ssl_functions_group cryption_group;
extern const struct ssl_functions_group code_group;

const struct ssl_functions_group *ssl_groups[] = {
    &hash_group,
    &cryption_group,
    &code_group,
    NULL
};

const struct ssl_functions_group **get_ssl_group_list(void)
{
    return ssl_groups;
}

int get_function_by_name(const char *name,
                        const struct ssl_functions_group **group_ptr,
                        const struct ssl_function **func_ptr)
{
    for (size_t i = 0; ssl_groups[i]; i++)
    {
        for (size_t j = 0; ssl_groups[i]->functions && ssl_groups[i]->functions[j]; j++)
        {
            if (strcmp(ssl_groups[i]->functions[j]->name, name) == 0)
            {
                *group_ptr = ssl_groups[i];
                *func_ptr  = ssl_groups[i]->functions[j];
                return (1); 
            }
        }
    }
    return (0);
}
