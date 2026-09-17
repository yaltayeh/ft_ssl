#include "ft_ssl.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

int run_hash_function(struct hash_function *hash_func, struct content_input *input)
{
    size_t ctx_size = hash_func->ctx_size;
    void *ctx = malloc(ctx_size);
    if (!ctx)
    {
        write(2, "Error: Memory allocation failed\n", 32);
        return (1);
    }

    uint8_t output[hash_func->output_length];
    ssize_t bytes_read;
    char buffer[1024];

    memset(output, 0, sizeof(output));
    while ((bytes_read = read_ci(input, buffer, sizeof(buffer))) > 0)
    {
        hash_func->hash(buffer, bytes_read, output, ctx);
    }

    if (bytes_read < 0)
    {
        write(2, "Error: Failed to read input\n", 28);
        free(ctx);
        return (1);
    }

    // Print the hash output in hexadecimal format
    for (size_t i = 0; i < hash_func->output_length; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");

    free(ctx);
    return (0);
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        write(2, "Usage: ./ft_ssl <command> [options] [file/string]\n", 50);
        return (1);
    }

    struct hash_function *hash_func = get_hash_function_by_name(argv[1]);
    if (hash_func == NULL)
    {
        write(2, "Error: Unknown command\n", 23);
        return (1);
    }

    struct content_input input = {0};
    input.type = CONTENT_TYPE_STRING;
    input.u.string.string = argv[2];
    input.u.string.length = strlen(input.u.string.string);

    run_hash_function(hash_func, &input);

    return (0);
}
