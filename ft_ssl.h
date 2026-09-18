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
            uint8_t is_open;
            uint8_t is_stdin;
            int fd;
        } file;
        struct
        {
            char *string;
            size_t length;
            size_t offset;
        } string;
    } u;

    struct content_input *next;
};

struct hash_function
{
    const char *name;         /* lowercase, matched against argv[1] */
    const char *display_name; /* uppercase, printed in the output lines */
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*final)(void *ctx, uint8_t *output);
    size_t ctx_size;
    size_t block_size;
    uint8_t output_size;
};

struct flags
{
    int p;
    int q;
    int r;
};

const char *get_store_buffer(void);
size_t get_store_buffer_len(void);
char **enable_store_buffer(void);
void disable_store_buffer(void);

struct content_input *create_ci_from_file(const char *filename);
struct content_input *create_ci_from_string(const char *string);
struct content_input *create_ci_from_stdin(void);
ssize_t read_ci(struct content_input *input, char *buffer, size_t len);
void free_ci(struct content_input *input);

struct hash_function *get_hash_function_by_name(const char *name);
const struct hash_function **get_hash_function_list(void);

size_t ft_strlen(const char *s);
void out_bytes(const char *data, size_t len);
void out_str(const char *s);
void out_hex(const uint8_t *data, size_t len);
void err_str(const char *s);

uint32_t rightrotate(uint32_t val, int n);
uint32_t leftrotate(uint32_t val, int n);
void little_endian_encode(uint64_t value, uint8_t *output, size_t output_size);
void big_endian_encode(uint64_t value, uint8_t *output, size_t output_size);

#endif // FT_SSL_H
