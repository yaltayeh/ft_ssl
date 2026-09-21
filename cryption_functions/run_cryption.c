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
static void print_cipher_error(const char *command, const char *entry, int err)
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

struct cipher_flags
{
    int         decrypt;       /* -d given (default is encrypt) */
    int         base64;        /* -a: base64 the ciphertext side */
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
static int parse_cipher_flags(int optc, char **optv, struct cipher_flags *flags)
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
static int resolve_key(const struct cipher_flags *flags, uint8_t key[8])
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

/*
** DES padding is unrelated to hash padding: every byte of pad, including a
** full extra block when the plaintext is already block-aligned, has the
** *count* of padding bytes as its value (PKCS#5-style). Only used when
** encrypting; decrypting removes it by reading the last output byte.
*/
static size_t pad_last_block(uint8_t *block, size_t used, size_t block_size)
{
    uint8_t pad_len = (uint8_t)(block_size - used);
    for (size_t i = used; i < block_size; i++)
        block[i] = pad_len;
    return (block_size);
}

static size_t unpad_last_block(uint8_t *block, size_t block_size)
{
    uint8_t pad_len = block[block_size - 1];
    if (pad_len == 0 || pad_len > block_size)
        return (block_size); /* malformed padding: emit as-is rather than crash */
    return (block_size - pad_len);
}

/*
** Processes one whole stream (file or stdin -> file or stdout), one block
** at a time, writing each block's result immediately - unlike hashing,
** there is no single final digest to wait for. CBC's chaining is handled
** here (cryption_func->needs_iv), not inside the DES core itself: the IV
** is this function's business, not the algorithm's, exactly like flags
** belongs to run_hash and not to hash_context.
*/
static int run_cryption_stream(const struct cryption_function *cryption_func,
                                struct content_input *input, int output_fd,
                                const uint8_t *key, uint8_t iv[8], int decrypt)
{
    void *ctx_mem = malloc(cryption_func->state_size);
    if (!ctx_mem)
    {
        err_str("ft_ssl: Error: Memory allocation failed\n");
        return (1);
    }
    struct cryption_context ctx = { .state = ctx_mem };
    cryption_func->init(&ctx, key);

    uint8_t block[8];
    uint8_t out_block[8];
    uint8_t prev_block[8]; /* holds the previous ciphertext block for CBC */
    int have_prev = 0;

    if (cryption_func->needs_iv)
    {
        memcpy(prev_block, iv, 8);
        have_prev = 1;
    }

    ssize_t n;
    size_t buffered = 0;
    errno = 0;

    while ((n = read_ci(input, (char *)block + buffered, 8 - buffered)) > 0 || buffered > 0)
    {
        buffered += (n > 0) ? (size_t)n : 0;
        if (buffered < 8 && n > 0)
            continue; /* keep filling this block */

        /* peek whether more data follows, to know if THIS block is last */
        char probe;
        ssize_t peek = 0;
        if (buffered == 8)
            peek = read_ci(input, &probe, 0); /* 0-length probe: see notes below */

        if (!decrypt && buffered < 8)
            buffered = pad_last_block(block, buffered, 8);

        if (decrypt)
        {
            if (cryption_func->needs_iv)
            {
                cryption_func->decrypt(&ctx, block, out_block);
                for (int i = 0; i < 8; i++)
                    out_block[i] ^= prev_block[i];
                memcpy(prev_block, block, 8);
            }
            else
            {
                cryption_func->decrypt(&ctx, block, out_block);
            }
        }
        else
        {
            uint8_t to_encrypt[8];
            memcpy(to_encrypt, block, 8);
            if (cryption_func->needs_iv)
                for (int i = 0; i < 8; i++)
                    to_encrypt[i] ^= prev_block[i];

            cryption_func->encrypt(&ctx, to_encrypt, out_block);

            if (cryption_func->needs_iv)
                memcpy(prev_block, out_block, 8);
        }

        size_t out_len = 8;
        if (decrypt && peek == 0) /* this was the last block: strip padding */
            out_len = unpad_last_block(out_block, 8);

        write(output_fd, out_block, out_len);
        buffered = 0;
        (void)have_prev;
    }

    free(ctx_mem);

    if (n < 0)
    {
        int err = errno ? errno : EIO;
        print_cipher_error(cryption_func->func.name, "read", err);
        return (1);
    }
    return (0);
}

int run_cryption(const struct ssl_function *func, int optc, char **optv)
{
    const struct cryption_function *cryption_func = (const struct cryption_function *)func;

    struct cipher_flags flags;
    if (!parse_cipher_flags(optc, optv, &flags))
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
        print_cipher_error(cryption_func->func.name,
                            flags.input_path ? flags.input_path : "stdin", errno);
        return (1);
    }

    int output_fd = 1; /* stdout */
    if (flags.output_path)
    {
        output_fd = open(flags.output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd < 0)
        {
            print_cipher_error(cryption_func->func.name, flags.output_path, errno);
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
