#include <string.h>
#include "code_functions.h"

extern const struct code_function base64_function;

const struct code_function *code_functions[] = {
    &base64_function,
    NULL
};

const struct ssl_functions_group code_group = {
    "Message Digest command",
    (const struct ssl_function **)code_functions,
    .run = run_code
};