#include "cryption_functions.h"
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
static void print_cryption_error(const char *command, const char *entry, int err)
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
** -k HEXKEY and -v HEXIV arrive as hex strings on argv; DES itself only
** ever wants raw bytes. Parses exactly `out_len` bytes (2 hex chars each),
** short hex strings are zero-padded on the right per the subject
** ("hex key FF1 becomes FF10000000000000"), long ones are truncated.
*/
static void parse_hex_into(const char *hex, uint8_t *out, size_t out_len)
{
    memset(out, 0, out_len);
    size_t hex_len = strlen(hex);

    for (size_t i = 0; i < out_len && i * 2 < hex_len; i++)
    {
        char byte_str[3] = { hex[i * 2], (i * 2 + 1 < hex_len) ? hex[i * 2 + 1] : '0', '\0' };
        out[i] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
}

struct cryption_flags
{
    int         decrypt;       /* -d given (default is encrypt) */
    int         base64;        /* -a: base64 the cryptiontext side */
    const char *input_path;    /* -i, NULL means stdin */
    const char *output_path;   /* -o, NULL means stdout */
    const char *key_hex;       /* -k, NULL if not given */
    const char *passphrase;    /* -p, NULL if not given */
    const char *salt_hex;      /* -s, NULL if not given */
    const char *iv_hex;        /* -v, NULL if not given */
};

/*
** All of DES's flags take the next argv token as their argument (-k, -p,
** -s, -v, -i, -o), unlike md5/sha256's -s. There is no "operand" concept
** here at all - des reads/writes exactly one stream, given by -i/-o or
** stdin/stdout - so there's no getopt-style "stop at the first filename"
** rule to apply; every flag is recognised wherever it appears.
*/
static int parse_cryption_flags(int optc, char **optv, struct cryption_flags *flags)
{
    memset(flags, 0, sizeof(*flags));

    for (int i = 0; i < optc; i++)
    {
        if (strcmp(optv[i], "-d") == 0)
            flags->decrypt = 1;
        else if (strcmp(optv[i], "-e") == 0)
            flags->decrypt = 0;
        else if (strcmp(optv[i], "-a") == 0)
            flags->base64 = 1;
        else if (strcmp(optv[i], "-i") == 0 && i + 1 < optc)
            flags->input_path = optv[++i];
        else if (strcmp(optv[i], "-o") == 0 && i + 1 < optc)
            flags->output_path = optv[++i];
        else if (strcmp(optv[i], "-k") == 0 && i + 1 < optc)
            flags->key_hex = optv[++i];
        else if (strcmp(optv[i], "-p") == 0 && i + 1 < optc)
            flags->passphrase = optv[++i];
        else if (strcmp(optv[i], "-s") == 0 && i + 1 < optc)
            flags->salt_hex = optv[++i];
        else if (strcmp(optv[i], "-v") == 0 && i + 1 < optc)
            flags->iv_hex = optv[++i];
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

/*
** Resolves the 64-bit key from whichever of -k / -p / interactive prompt
** the user gave, per the subject's precedence (a directly-given -k skips
** password handling entirely). PBKDF and interactive-prompt paths are not
** implemented yet - both currently fall through to a stub that must be
** replaced before this is usable end-to-end; -k works today.
*/
static int resolve_key(const struct cryption_flags *flags, uint8_t key[8])
{
    if (flags->key_hex)
    {
        parse_hex_into(flags->key_hex, key, 8);
        return (1);
    }
    if (flags->passphrase)
    {
        /* TODO: run_pbkdf(flags->passphrase, flags->salt_hex, key, 8); */
        err_str("ft_ssl: Error: -p (PBKDF) not implemented yet\n");
        return (0);
    }
    /* TODO: prompt interactively via getpass()/readpassphrase(), then PBKDF */
    err_str("ft_ssl: Error: no key given and interactive prompt not implemented yet\n");
    return (0);
}

static void xor_block(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] ^= src[i];
}

static int run_encryption_stream(const struct cryption_function *cryption_func,
                                    struct content_input *input,
                                    struct cryption_context *ctx,
                                    uint8_t prev_block[8],
                                    int output_fd)
{
    uint8_t block[8];
    uint8_t out_block[8];

    while (1)
    {
        ssize_t n = read_ci(input, (char *)block, 8);
        if (n < 0)
            return (-1);

        if (n < 8)
        {
            uint8_t pad_len = (uint8_t)(8 - n);
            for (ssize_t i = n; i < 8; i++)
                block[i] = pad_len;
        }

        if (cryption_func->needs_iv)
            xor_block(block, prev_block, 8);

        cryption_func->encrypt(ctx, block, out_block);

        if (cryption_func->needs_iv)
            memcpy(prev_block, out_block, 8);

        write(output_fd, out_block, 8);

        if (n < 8)
            break; /* that was the (now padded) final block */
    }
    return (0);
}

static int run_decryption_stream(const struct cryption_function *cryption_func,
                                    struct content_input *input,
                                    struct cryption_context *ctx,
                                    uint8_t prev_block[8],
                                    int output_fd)
{
    /* DECRYPT: ciphertext is always a multiple of 8 bytes, so every
    ** read_ci call returns exactly 8 (a real block) or 0 (done) - never
    ** something in between. That means we can't tell whether a given
    ** 8-byte block is the last one until the *next* read confirms EOF.
    ** One-block lookahead is unavoidable here, unlike encryption. */
    uint8_t block[8];
    uint8_t out_block[8];
    uint8_t pending[8];
    int have_pending = 0;
    
    while (1)
    {
        ssize_t n = read_ci(input, (char *)block, 8);
        if (n < 0)
            return (-1);

        if (n == 0)
            break; /* nothing new; `pending` (if any) is the final block */

        if (n != 8)
        {
            /* malformed ciphertext: not a multiple of the block size */
            err_str("ft_ssl: Error: ciphertext is not a multiple of the block size\n");
            return (-2);
        }

        if (have_pending)
        {
            /* pending is confirmed NOT last: decrypt & write it as-is */
            uint8_t decrypted_prev[8];
            cryption_func->decrypt(ctx, pending, decrypted_prev);
            if (cryption_func->needs_iv)
            {
                xor_block(decrypted_prev, prev_block, 8);
                memcpy(prev_block, pending, 8);
            }
            write(output_fd, decrypted_prev, 8);
        }

        memcpy(pending, block, 8);
        have_pending = 1;
    }

    if (have_pending)
    {
        /* pending is now confirmed to be the final block: decrypt it
        ** and strip its padding. */
        cryption_func->decrypt(ctx, pending, out_block);
        if (cryption_func->needs_iv)
            xor_block(out_block, prev_block, 8);

        uint8_t pad_len = out_block[7];
        size_t out_len = (pad_len >= 1 && pad_len <= 8) ? (8 - pad_len) : 8;

        write(output_fd, out_block, out_len);
    }
    return (0);
}

static int run_cryption_stream(const struct cryption_function *cryption_func,
                                struct content_input *input, int output_fd,
                                const uint8_t *key, uint8_t iv[8], int decrypt)
{
    void *state = malloc(cryption_func->state_size);
    if (!state)
    {
        err_str("ft_ssl: Error: Memory allocation failed\n");
        return (1);
    }
    struct cryption_context ctx = { .state = state };
    cryption_func->init(&ctx, key);

    uint8_t prev_block[8];
    if (cryption_func->needs_iv)
        memcpy(prev_block, iv, 8);

    int status = 0;
    if (decrypt)
        status = run_decryption_stream(cryption_func, input, &ctx, prev_block, output_fd);
    else
        status = run_encryption_stream(cryption_func, input, &ctx, prev_block, output_fd);

    free(state);
    if (status == -1)
    {
        int err = errno ? errno : EIO;
        print_cryption_error(cryption_func->base.name, "read", err);
        return (-1);
    }
    else if (status == -2)
        return (-1);
    return (0);
}


int run_cryption(const struct ssl_function *func, int optc, char **optv)
{
    const struct cryption_function *cryption_func = (const struct cryption_function *)func;

    struct cryption_flags flags;
    if (!parse_cryption_flags(optc, optv, &flags))
        return (1);

    uint8_t key[8];
    if (!resolve_key(&flags, key))
        return (1);

    uint8_t iv[8] = {0};
    if (cryption_func->needs_iv && flags.iv_hex)
        parse_hex_into(flags.iv_hex, iv, 8);

    struct content_input *input = flags.input_path
        ? create_ci_from_file(flags.input_path)
        : create_ci_from_stdin();
    if (!input)
    {
        print_cryption_error(cryption_func->base.name,
                            flags.input_path ? flags.input_path : "stdin", errno);
        return (1);
    }

    int output_fd = 1; /* stdout */
    if (flags.output_path)
    {
        output_fd = open(flags.output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd < 0)
        {
            print_cryption_error(cryption_func->base.name, flags.output_path, errno);
            free_ci(input);
            return (1);
        }
    }

    /* TODO: flags.base64 - wrap output_fd's writes through base64 encode
    ** when encrypting (or decode the input stream when decrypting) once
    ** the base64 module exists. */

    int status = run_cryption_stream(cryption_func, input, output_fd, key, iv, flags.decrypt);

    if (flags.output_path)
        close(output_fd);
    free_ci(input);

    return (status);
}
