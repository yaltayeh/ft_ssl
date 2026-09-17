#include "ft_ssl.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

void print_usage(void)
{
    write(2, "Usage: ./ft_ssl <command> [options] [file/string]\n", 50);
}

void print_ouput(struct hash_function *hash_func, struct content_input *ci, uint8_t *output, struct flags *flags)
{
    if (flags->q)
    {
        for (size_t i = 0; i < hash_func->output_size; i++)
        {
            printf("%02x", output[i]);
        }
        printf("\n");
    }
    else if (flags->r)
    {
        for (size_t i = 0; i < hash_func->output_size; i++)
        {
            printf("%02x", output[i]);
        }
        if (ci->type == CONTENT_TYPE_FILE)
            printf(" %s\n", ci->u.file.filename);
        else if (ci->type == CONTENT_TYPE_STRING)
            printf("(\"%s\")\n", ci->u.string.string);
    }
    else
    {
        printf("%s (", hash_func->name);
        if (ci->type == CONTENT_TYPE_FILE)
            printf("%s (%s) = ", hash_func->name, ci->u.file.filename);
        else if (ci->type == CONTENT_TYPE_STRING)
            printf("%s (\"%s\") = ", hash_func->name, ci->u.string.string);

        for (size_t i = 0; i < hash_func->output_size; i++)
        {
            printf("%02x", output[i]);
        }
        printf("\n");
    }
}

int run_hash_function(struct hash_function *hash_func, struct content_input *input, struct flags *flags)
{
    size_t ctx_size = hash_func->ctx_size;
    void *ctx = malloc(ctx_size);
    if (!ctx)
    {
        write(2, "Error: Memory allocation failed\n", 32);
        return (1);
    }
    hash_func->init(ctx);

    ssize_t bytes_read;
    char buffer[1024];

    while ((bytes_read = read_ci(input, buffer, sizeof(buffer))) > 0)
    {
        hash_func->update(ctx, (const uint8_t *)buffer, bytes_read);
    }

    
    if (bytes_read < 0)
    {
        write(2, "Error: Failed to read input\n", 28);
        free(ctx);
        return (1);
    }
    
    uint8_t output[hash_func->output_size];
    hash_func->final(ctx, output);
    free(ctx);
    
    print_ouput(hash_func, input, output, flags);

    return (0);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_usage();
        return (1);
    }

    struct hash_function *hash_func = get_hash_function_by_name(argv[1]);
    if (hash_func == NULL)
    {
        write(2, "Error: Unknown command\n", 23);
        return (1);
    }
    
    struct flags flags = {0, 0, 0};
    
    struct content_input *ci = NULL;
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            flags.p = 1;
        }
        else if (strcmp(argv[i], "-q") == 0)
        {
            flags.q = 1;
        }
        else if (strcmp(argv[i], "-r") == 0)
        {
            flags.r = 1;
        }
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
        {
            struct content_input *input = create_ci_from_string(argv[i + 1], ci);
            if (!input)
            {
                free_ci(ci);
                write(2, "Error: Memory allocation failed\n", 32);
                return (1);
            }
            ci = input;
            
            i++; // Skip the next argument since it's the string
        }
        else
        {
            struct content_input *input = create_ci_from_file(argv[i], ci);
            if (!input)
            {
                free_ci(ci);
                write(2, "Error: Memory allocation failed\n", 32);
                return (1);
            }
            ci = input;
        }
    }

    if (ci == NULL || flags.p)
    {
        struct content_input *ci = create_ci_from_stdin(ci);
        if (!ci)
        {
            write(2, "Error: Memory allocation failed\n", 32);
            return (1);
        }
        free_ci(ci);
    }

    while (ci)
    {
        if (run_hash_function(hash_func, ci, &flags) != 0)
        {
            free_ci(ci);
            return (1);
        }
        struct content_input *next = ci->next;
        free_ci(ci);
        ci = next;
    }

    return (0);
}
