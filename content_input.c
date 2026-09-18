#include "ft_ssl.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

static char *store_buffer = NULL;
static size_t store_buffer_len = 0;
static int is_store_buffer_enabled = 0;

const char *get_store_buffer(void)
{
    return store_buffer;
}

size_t get_store_buffer_len(void)
{
    return store_buffer_len;
}

char **enable_store_buffer(void)
{
    is_store_buffer_enabled = 1;
    store_buffer_len = 0;
    if (store_buffer)
        free(store_buffer);
    store_buffer = malloc(1);
    if (store_buffer)
        store_buffer[0] = '\0';
    else
        return NULL;
    return &store_buffer;
}

void disable_store_buffer(void)
{
    is_store_buffer_enabled = 0;
    if (store_buffer)
    {
        free(store_buffer);
        store_buffer = NULL;
    }
    store_buffer_len = 0;
}

static char *add_to_store_buffer(const char *data, size_t len)
{
    if (!is_store_buffer_enabled)
        return NULL;

    char *new_store_buffer = realloc(store_buffer, store_buffer_len + len + 1);
    if (!new_store_buffer)
        return NULL;

    store_buffer = new_store_buffer;
    memcpy(store_buffer + store_buffer_len, data, len);
    store_buffer_len += len;
    store_buffer[store_buffer_len] = '\0';

    return store_buffer;
}

struct content_input *create_ci_from_file(const char *filename)
{
    struct content_input *ci = malloc(sizeof(struct content_input));
    if (!ci)
        return NULL;

    ci->type = CONTENT_TYPE_FILE;
    ci->u.file.filename = strdup(filename);
    if (!ci->u.file.filename)
    {
        free(ci);
        return NULL;
    }
    ci->u.file.fd = -1;
    ci->u.file.is_open = 0;
    ci->u.file.is_stdin = 0;

    ci->next = NULL;
    return ci;
}

struct content_input *create_ci_from_string(const char *string)
{
    struct content_input *ci = malloc(sizeof(struct content_input));
    if (!ci)
        return NULL;

    ci->type = CONTENT_TYPE_STRING;
    ci->u.string.string = strdup(string);
    if (!ci->u.string.string)
    {
        free(ci);
        return NULL;
    }
    ci->u.string.length = strlen(string);
    ci->u.string.offset = 0;

    ci->next = NULL;
    return ci;
}

struct content_input *create_ci_from_stdin(void)
{
    struct content_input *ci = malloc(sizeof(struct content_input));
    if (!ci)
        return NULL;

    ci->type = CONTENT_TYPE_FILE;
    ci->u.file.filename = strdup("stdin");
    ci->u.file.is_open = 1;
    ci->u.file.is_stdin = 1;
    if (!ci->u.file.filename)
    {
        free(ci);
        return NULL;
    }
    ci->u.file.fd = STDIN_FILENO;

    ci->next = NULL;
    return ci;
}

void free_ci(struct content_input *input)
{
    if (!input)
        return;

    if (input->type == CONTENT_TYPE_FILE)
    {
        if (input->u.file.fd >= 0 && input->u.file.fd != STDIN_FILENO)
            close(input->u.file.fd);
        free(input->u.file.filename);
    }
    else if (input->type == CONTENT_TYPE_STRING)
    {
        free(input->u.string.string);
    }

    if (input->next)
        free_ci(input->next);

    free(input);
}

ssize_t read_ci(struct content_input *input, char *buffer, size_t len)
{
    if (input->type == CONTENT_TYPE_FILE)
    {
        if (input->u.file.is_open == 0 && input->u.file.fd < 0)
        {
            input->u.file.fd = open(input->u.file.filename, O_RDONLY);
            if (input->u.file.fd < 0)
                return (-1);
            input->u.file.is_open = 1;
        }
        int bytes_read = read(input->u.file.fd, buffer, len);
        if (bytes_read < 0)
            return (-1);
        if (is_store_buffer_enabled)
        {
            char *stored = add_to_store_buffer(buffer, bytes_read);
            if (!stored)
                return (-1);
        }
        return bytes_read;
    }
    else if (input->type == CONTENT_TYPE_STRING)
    {
        if (input->u.string.offset >= input->u.string.length)
            return 0;
        
        char *src = input->u.string.string + input->u.string.offset;
        size_t remaining = input->u.string.length - input->u.string.offset;
        size_t to_copy = (len < remaining) ? len : remaining;
        memcpy(buffer, src, to_copy);
        input->u.string.offset += to_copy;
        return to_copy;
    }
    return (-1);
}
