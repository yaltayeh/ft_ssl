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

const char *get_store_buffer(void);
size_t get_store_buffer_len(void);
char **enable_store_buffer(void);
void disable_store_buffer(void);

int append_ci(struct content_input *new_ci, struct content_input **head,
                     struct content_input **tail);

struct content_input *create_ci_from_file(const char *filename);
struct content_input *create_ci_from_string(const char *string);
struct content_input *create_ci_from_stdin(void);
ssize_t read_ci(struct content_input *input, char *buffer, size_t len);
void free_ci(struct content_input *input);

size_t ft_strlen(const char *s);
void out_bytes(const char *data, size_t len);
void out_str(const char *s);
void out_hex(const uint8_t *data, size_t len);
void err_str(const char *s);

uint64_t rightrotate(uint64_t val, size_t n, size_t size);
uint64_t leftrotate(uint64_t val, size_t n, size_t size);
void little_endian_encode(uint64_t value, uint8_t *output, size_t output_size);
void big_endian_encode(uint64_t value, uint8_t *output, size_t output_size);
uint64_t permutation(uint64_t input, const uint8_t *table,
                             size_t table_size, size_t input_bit_width);

#endif // FT_SSL_H
