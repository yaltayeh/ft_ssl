#include <string.h>
#include "cryption_functions.h"

extern const struct cryption_function des_cryption_function;

const struct cryption_function *cryption_functions[] = {
    &des_cryption_function,
    NULL
};

const struct ssl_functions_group cryption_group = {
    "Message Digest command",
    (const struct ssl_function **)cryption_functions,
    .run = run_cryption 
};