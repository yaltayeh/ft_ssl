#include "cryption_functions.h"

int run_cipher(const struct ssl_function *func,
                int optc,
                char **optv)
{
    const struct cryption_function *cryption_func = (const struct cryption_function *)func;

    (void)cryption_func;
    (void)optc;
    (void)optv;
    return (0);
}
