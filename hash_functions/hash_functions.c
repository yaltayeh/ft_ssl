#include "hash_functions.h"
#include <string.h>

extern const struct hash_function md5_hash_function;
extern const struct hash_function sha256_hash_function;
extern const struct hash_function sha224_hash_function;
extern const struct hash_function sha512_hash_function;
extern const struct hash_function sha384_hash_function;

static const struct hash_function *hash_functions[] = {
    &md5_hash_function,
    &sha256_hash_function,
    &sha224_hash_function,
    &sha512_hash_function,
    &sha384_hash_function,
    NULL
};

const struct ssl_functions_group hash_group = {
    "Message Digest command",
    (const struct ssl_function **)hash_functions,
    .run = run_hash 
};
