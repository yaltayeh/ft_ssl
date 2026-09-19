#include "hash_functions.h"
#include "../ft_ssl.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
** ft_ssl: <command>: <entry>: <reason>
** One failing file or string never aborts the run; it only contributes to the
** non-zero exit status.
*/
static void print_entry_error(const char *command, const char *entry, int err)
{
    err_str("ft_ssl: ");
    err_str(command);
    err_str(": ");
    err_str(entry);
    err_str(": ");
    err_str(strerror(err));
    err_str("\n");
}

/*
** STDIN's own line never honours -r: with -p it is always ("<content>")= <hash>,
** and without -p it is (stdin)= <hash>. The -p + -q pair is a separate format
** entirely: the raw STDIN bytes on their own line, then the bare digest.
*/
static void print_stdin_output(struct hash_function *hash_func, uint8_t *output,
                               struct flags *flags)
{
    const char *content = get_store_buffer();
    size_t len = content ? get_store_buffer_len() : 0;

    if (flags->p)
    {
        if (flags->q)
        {
            out_bytes(content, len);
            if (len == 0 || content[len - 1] != '\n')
                out_str("\n");
            out_hex(output, hash_func->output_size);
            out_str("\n");
            return;
        }
        /* the echoed content is quoted without its trailing newline */
        if (len > 0 && content[len - 1] == '\n')
            len--;
        out_str("(\"");
        out_bytes(content, len);
        out_str("\")= ");
    }
    else if (!flags->q)
    {
        out_str("(stdin)= ");
    }

    out_hex(output, hash_func->output_size);
    out_str("\n");
}

static void print_file_or_string_output(struct hash_function *hash_func,
                                        struct content_input *ci,
                                        uint8_t *output, struct flags *flags)
{
    int is_file = (ci->type == CONTENT_TYPE_FILE);
    const char *name = is_file ? ci->u.file.filename : ci->u.string.string;

    /* -q wins over -r: digest only */
    if (flags->q)
    {
        out_hex(output, hash_func->output_size);
        out_str("\n");
        return;
    }

    if (flags->r)
    {
        out_hex(output, hash_func->output_size);
        out_str(" ");
        if (!is_file)
            out_str("\"");
        out_str(name);
        if (!is_file)
            out_str("\"");
        out_str("\n");
        return;
    }

    out_str(hash_func->display_name);
    out_str(" (");
    if (!is_file)
        out_str("\"");
    out_str(name);
    if (!is_file)
        out_str("\"");
    out_str(") = ");
    out_hex(output, hash_func->output_size);
    out_str("\n");
}

static void print_ouput(struct hash_function *hash_func, struct content_input *ci,
                        uint8_t *output, struct flags *flags)
{
    if (ci->type == CONTENT_TYPE_FILE && ci->u.file.is_stdin)
        print_stdin_output(hash_func, output, flags);
    else
        print_file_or_string_output(hash_func, ci, output, flags);
}

static void run_hash_update(struct hash_function *hash_func, struct hash_context *ctx, const uint8_t *data, size_t len)
{
    ctx->total_len += len;

    if (ctx->buffer_len > 0)
    {
        size_t space_in_buffer = hash_func->block_size - ctx->buffer_len;
        size_t to_copy = (len < space_in_buffer) ? len : space_in_buffer;
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == hash_func->block_size)
        {
            hash_func->process(ctx, ctx->buffer);
            ctx->buffer_len = 0; // Reset buffer length after processing
        }
    }
    while (len >= hash_func->block_size)
    {
        hash_func->process(ctx, data);
        data += hash_func->block_size;
        len -= hash_func->block_size; // Simulate processing a block
    }
    if (len > 0)
    {
        // Store remaining data in the buffer
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

struct hash_context *init_hash_context(struct hash_function *hash_func)
{
    size_t total_size = sizeof(struct hash_context) + hash_func->state_size + hash_func->block_size;

    struct hash_context *ctx = malloc(total_size);
    if (ctx == NULL)
        return (NULL);

    memset(ctx, 0, sizeof(*ctx));

    uint8_t *base = (uint8_t *)ctx;
    ctx->state  = base + sizeof(struct hash_context);
    ctx->buffer = base + sizeof(struct hash_context) + hash_func->state_size;

    return (ctx);
}

void free_hash_context(struct hash_context *ctx)
{
    free(ctx);
}

int run_hash_function(struct hash_function *hash_func, struct content_input *ci,
                      struct flags *flags, const char *command)
{
    
    struct hash_context *ctx;

    ctx = init_hash_context(hash_func);
    if (ctx == NULL)
    {
        err_str("ft_ssl: Error: Memory allocation failed\n");
        return (1);
    }
    hash_func->init(ctx);

    ssize_t bytes_read;
    char buffer[1024];

    int store_data = flags->p && ci->type == CONTENT_TYPE_FILE && ci->u.file.is_stdin;
    if (store_data && enable_store_buffer() == NULL)
    {
        err_str("ft_ssl: Error: Memory allocation failed\n");
        free_hash_context(ctx);
        return (1);
    }

    errno = 0;
    while ((bytes_read = read_ci(ci, buffer, sizeof(buffer))) > 0)
        run_hash_update(hash_func, ctx, (uint8_t *)buffer, bytes_read);

    if (bytes_read < 0)
    {
        int err = errno ? errno : EIO;

        if (ci->type == CONTENT_TYPE_FILE)
            print_entry_error(command, ci->u.file.filename, err);
        else
            print_entry_error(command, ci->u.string.string, err);

        if (store_data)
            disable_store_buffer();
        free_hash_context(ctx);
        return (1);
    }

    uint8_t output[hash_func->output_size];
    hash_func->final(ctx, output);
    free_hash_context(ctx);

    print_ouput(hash_func, ci, output, flags);

    if (store_data)
        disable_store_buffer();

    return (0);
}

int run_hash(struct hash_function *hash_func, const char *command, int optc,
             char **optv)
{
    struct flags flags = {0, 0, 0};
    struct content_input *ci = NULL;
    struct content_input *last_ci = NULL;
    int seen_file_operand = 0;

    for (int i = 0; i < optc; i++)
    {
        struct content_input *new_ci;

        /*
        ** Option parsing stops at the first bare filename operand, the way the
        ** conventional getopt rule works: from that point on every remaining
        ** token is a literal filename, even one that looks like a flag. The
        ** subject's transcript relies on this:
        **     ft_ssl md5 -r -p -s "foo" file -s "bar"
        ** prints the digest of "foo", then of file, and then fails on *both*
        ** "-s" and "bar" as missing files - even though that trailing -s does
        ** have an argument after it. A string given by -s is an option
        ** argument, not an operand, so it does not stop the parsing.
        */
        if (seen_file_operand)
        {
            new_ci = create_ci_from_file(optv[i]);
        }
        else if (strcmp(optv[i], "-p") == 0)
        {
            flags.p = 1;
            continue;
        }
        else if (strcmp(optv[i], "-q") == 0)
        {
            flags.q = 1;
            continue;
        }
        else if (strcmp(optv[i], "-r") == 0)
        {
            flags.r = 1;
            continue;
        }
        else if (strcmp(optv[i], "-s") == 0 && i + 1 < optc)
        {
            new_ci = create_ci_from_string(optv[i + 1]);
            i++; /* the string is consumed, never re-read as a filename */
        }
        else
        {
            /* a trailing -s with no argument lands here too, and likewise
            ** becomes a (failing) filename named "-s" */
            new_ci = create_ci_from_file(optv[i]);
            seen_file_operand = 1;
        }

        if (!append_ci(new_ci, &ci, &last_ci))
        {
            err_str("ft_ssl: Error: Memory allocation failed\n");
            free_ci(ci);
            return (1);
        }
    }

    /* STDIN is used when nothing else was given, or whenever -p is set, and is
    ** always processed first regardless of where -p appeared in optv. */
    if (ci == NULL || flags.p)
    {
        struct content_input *stdin_ci = create_ci_from_stdin();
        if (!stdin_ci)
        {
            err_str("ft_ssl: Error: Memory allocation failed\n");
            free_ci(ci);
            return (1);
        }
        stdin_ci->next = ci;
        ci = stdin_ci;
    }

    int status = 0;
    while (ci)
    {
        struct content_input *next = ci->next;

        if (run_hash_function(hash_func, ci, &flags, command) != 0)
            status = 1;

        ci->next = NULL; /* detach before freeing: free_ci frees the whole tail */
        free_ci(ci);
        ci = next;
    }
    return (status);
}
