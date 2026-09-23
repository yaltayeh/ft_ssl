#include "code_functions.h"
#include "../ft_ssl.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>

/*
** Same error-reporting shape as run_hash's print_entry_error:
** ft_ssl: <command>: <entry>: <reason>
*/
static void print_code_error(const char *command, const char *entry, int err)
{
    err_str("ft_ssl: ");
    err_str(command);
    err_str(": ");
    err_str(entry);
    err_str(": ");
    err_str(strerror(err));
    err_str("\n");
}

struct code_flags
{
    int         decode;       /* -d given (default is encrypt) */
    const char *input_path;    /* -i, NULL means stdin */
    const char *output_path;   /* -o, NULL means stdout */
};

static int parse_code_flags(int optc, char **optv, struct code_flags *flags)
{
    memset(flags, 0, sizeof(*flags));

    for (int i = 0; i < optc; i++)
    {
        if (strcmp(optv[i], "-d") == 0)
            flags->decode = 1;
        else if (strcmp(optv[i], "-e") == 0)
            flags->decode = 0;
        else if (strcmp(optv[i], "-i") == 0 && i + 1 < optc)
            flags->input_path = optv[++i];
        else if (strcmp(optv[i], "-o") == 0 && i + 1 < optc)
            flags->output_path = optv[++i];
        else
        {
            err_str("ft_ssl: unknown option '");
            err_str(optv[i]);
            err_str("'\n");
            return (0);
        }
    }
    return (1);
}

static ssize_t read_code_filtered(struct content_input *input, uint8_t *buffer, size_t len)
{
    size_t filled = 0;

    while (filled < len)
    {
        char c;
        ssize_t n = read_ci(input, &c, 1);
        if (n < 0)
            return (-1);
        if (n == 0)
            break;

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            continue;

        buffer[filled++] = (uint8_t)c;
    }
    return (ssize_t)filled;
}

#include <stdio.h>

static int run_code_stream(const struct code_function *code_func,
                            struct content_input *input, int outfd,
                            int decode)
{
    size_t in_size  = decode ? code_func->codes_size : code_func->text_size;
    size_t out_size = decode ? code_func->text_size : code_func->codes_size;

    uint8_t *in_block = malloc(in_size);
    if (!in_block)
        return (-1);
    uint8_t *out_block = malloc(out_size);
    if (!out_block)
        return (free(in_block), -1);

    int err = 0;
    while (err == 0)
    {
        ssize_t n = decode
            ? read_code_filtered(input, in_block, in_size)
            : read_ci(input, (char *)in_block, in_size);

        if (n < 0) { err = -1; break; }
        if (n == 0) break;

        if ((size_t)n < in_size)
        {
            if (decode)
                memset(in_block + n, 'A', in_size - n);
            else
                memset(in_block + n, 0, in_size - n);
        }

        if (decode)
        {
            int pad_count = 0;
            for (size_t i = 0; i < in_size; i++)
                if (in_block[i] == '=')
                    pad_count++;

            if (code_func->decode(in_block, out_block) != 0)
            {
                err_str("ft_ssl: Error: invalid base64 input\n");
                err = -1;
                break;
            }

            size_t valid_bytes = out_size - (size_t)pad_count;
            write(outfd, out_block, valid_bytes);
        }
        else
        {
            code_func->encode(in_block, out_block);

            if ((size_t)n < in_size)
            {
                size_t valid_codes = ((size_t)n * 8 + 5) / 6;
                for (size_t i = valid_codes; i < out_size; i++)
                    out_block[i] = '=';
            }
            write(outfd, out_block, out_size);
        }

        if ((size_t)n < in_size)
            break;   /* كان هذا فعليًا آخر بلوك (قراءة جزئية) */
    }
    free(in_block);
    free(out_block);
    return (err);
}

int run_code(const struct ssl_function *func, int optc, char **optv)
{
    const struct code_function *code_func = (const struct code_function *)func;

    struct code_flags flags;
    if (!parse_code_flags(optc, optv, &flags))
        return (1);

    struct content_input *input = flags.input_path
        ? create_ci_from_file(flags.input_path)
        : create_ci_from_stdin();
    if (!input)
    {
        print_code_error(code_func->func.name,
                            flags.input_path ? flags.input_path : "stdin", errno);
        return (1);
    }

    int outfd = 1; /* stdout */
    if (flags.output_path)
    {
        outfd = open(flags.output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (outfd < 0)
        {
            print_code_error(code_func->func.name, flags.output_path, errno);
            free_ci(input);
            return (1);
        }
    }

    int status = run_code_stream(code_func, input, outfd, flags.decode);

    if (flags.output_path)
        close(outfd);
    free_ci(input);

    return (status);
}
