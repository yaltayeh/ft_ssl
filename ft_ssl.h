#ifndef FT_SSL_H
#define FT_SSL_H

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

enum content_type
{
    CONTENT_TYPE_FILE = 0,
    CONTENT_TYPE_STRING = 1,
};

struct content_input
{
    uint8_t type;

    union
    {
        struct
        {
            char *filename;
            int fd;
        } file;
        struct
        {
            char *string;
            size_t length;
            size_t offset;
        } string;
    } u;
};

struct hash_function
{
    const char *name;
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*final)(void *ctx, uint8_t *output);
    size_t ctx_size;
    size_t block_size;
    uint8_t hash_size;
};

struct content_input *create_ci_from_file(const char *filename);
struct content_input *create_ci_from_string(const char *string);
struct content_input *create_ci_from_stdin(void);
ssize_t read_ci(struct content_input *input, char *buffer, size_t len);
void free_ci(struct content_input *input);

struct hash_function *get_hash_function_by_name(const char *name);

#endif // FT_SSL_H
