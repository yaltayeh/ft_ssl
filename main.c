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

static void print_hex(uint8_t *output, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", output[i]);
}

static void print_stdin_output(struct hash_function *hash_func, uint8_t *output, struct flags *flags)
{
    if (flags->p)
    {
        if (flags->q)
        {
            // سطر خام مستقل لمحتوى stdin، بدون أقواس ولا اسم خوارزمية
            printf("%s\n", get_store_buffer());
            print_hex(output, hash_func->output_size);
            printf("\n");
            return;
        }
        printf("(\"%s\")= ", get_store_buffer());
    }
    else if (!flags->q)
    {
        printf("(stdin)= ");
    }
    // ملاحظة: -r لا تؤثر إطلاقًا على صيغة stdin، ولذلك لا يوجد أي فحص لـ flags->r هنا

    print_hex(output, hash_func->output_size);
    printf("\n");
}

static void print_file_or_string_output(struct hash_function *hash_func, struct content_input *ci,
                                         uint8_t *output, struct flags *flags)
{
    if (flags->q)
    {
        print_hex(output, hash_func->output_size);
        printf("\n");
        return;
    }

    if (flags->r)
    {
        print_hex(output, hash_func->output_size);
        if (ci->type == CONTENT_TYPE_FILE)
            printf(" %s\n", ci->u.file.filename);
        else if (ci->type == CONTENT_TYPE_STRING)
            printf(" \"%s\"\n", ci->u.string.string);
        return;
    }

    // الصيغة الافتراضية (بدون -q ولا -r)
    if (ci->type == CONTENT_TYPE_FILE)
        printf("%s (%s) = ", hash_func->name, ci->u.file.filename);
    else if (ci->type == CONTENT_TYPE_STRING)
        printf("%s (\"%s\") = ", hash_func->name, ci->u.string.string);

    print_hex(output, hash_func->output_size);
    printf("\n");
}

void print_ouput(struct hash_function *hash_func, struct content_input *ci,
                  uint8_t *output, struct flags *flags)
{
    if (ci->type == CONTENT_TYPE_FILE && ci->u.file.is_stdin)
        print_stdin_output(hash_func, output, flags);
    else
        print_file_or_string_output(hash_func, ci, output, flags);
}


int run_hash_function(struct hash_function *hash_func, struct content_input *ci, struct flags *flags)
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

    int store_data = flags->p && (ci->type == CONTENT_TYPE_FILE && ci->u.file.is_stdin);
    if (store_data && enable_store_buffer() == NULL)
    {
        write(2, "Error: Memory allocation failed\n", 32);
        free(ctx);
        return (1);
    }

    while ((bytes_read = read_ci(ci, buffer, sizeof(buffer))) > 0)
    {
        hash_func->update(ctx, (const uint8_t *)buffer, bytes_read);
    }

    if (bytes_read < 0)
    {
        if (ci->type == CONTENT_TYPE_FILE)
            perror(ci->u.file.filename);
        else if (ci->type == CONTENT_TYPE_STRING)
            perror(ci->u.string.string);
        else
            write(2, "Error: Failed to read input\n", 28);
            
        if (store_data)
            disable_store_buffer();
        free(ctx);
        return (1);
    }
    
    uint8_t output[hash_func->output_size];
    hash_func->final(ctx, output);
    free(ctx);
    
    print_ouput(hash_func, ci, output, flags);

    if (store_data)
        disable_store_buffer();

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
    struct content_input *last_ci = NULL;

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
            struct content_input *new_ci = create_ci_from_string(argv[i + 1]);
            if (!new_ci)
            {
                free_ci(ci);
                write(2, "Error: Memory allocation failed\n", 32);
                return (1);
            }
            if (last_ci)
                last_ci->next = new_ci;
            else
                ci = new_ci;
            last_ci = new_ci;
            
            i++; // Skip the next argument since it's the string
        }
        else
        {
            struct content_input *new_ci = create_ci_from_file(argv[i]);
            if (!new_ci)
            {
                free_ci(ci);
                write(2, "Error: Memory allocation failed\n", 32);
                return (1);
            }
            if (last_ci)
                last_ci->next = new_ci;
            else
                ci = new_ci;
            last_ci = new_ci;
        }
    }

    if (ci == NULL || flags.p)
    {
        struct content_input *new_ci = create_ci_from_stdin();
        if (!new_ci)
        {
            write(2, "Error: Memory allocation failed\n", 32);
            return (1);
        }
        new_ci->next = ci;
        ci = new_ci;
    }

    while (ci)
    {
        run_hash_function(hash_func, ci, &flags);
        struct content_input *next = ci->next;
        ci->next = NULL; // Disconnect the current node from the list before freeing
        free_ci(ci);
        ci = next;
    }

    return (0);
}
