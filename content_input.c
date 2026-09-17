#include "ft_ssl.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

struct content_input *create_ci_from_file(const char *filename)
{
    struct content_input *input = malloc(sizeof(struct content_input));
    if (!input)
        return NULL;

    input->type = CONTENT_TYPE_FILE;
    input->u.file.filename = strdup(filename);
    if (!input->u.file.filename)
    {
        free(input);
        return NULL;
    }
    input->u.file.fd = open(filename, O_RDONLY);
    if (input->u.file.fd < 0)
    {
        free(input->u.file.filename);
        free(input);
        return NULL;
    }

    return input;
}

struct content_input *create_ci_from_string(const char *string)
{
    struct content_input *input = malloc(sizeof(struct content_input));
    if (!input)
        return NULL;

    input->type = CONTENT_TYPE_STRING;
    input->u.string.string = strdup(string);
    if (!input->u.string.string)
    {
        free(input);
        return NULL;
    }
    input->u.string.length = strlen(string);
    input->u.string.offset = 0;

    return input;
}

struct content_input *create_ci_from_stdin(void)
{
    struct content_input *input = malloc(sizeof(struct content_input));
    if (!input)
        return NULL;

    input->u.file.filename = strdup("stdin");
    if (!input->u.file.filename)
    {
        free(input);
        return NULL;
    }
    input->u.file.fd = STDIN_FILENO;

    return input;
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

    free(input);
}

ssize_t read_ci(struct content_input *input, char *buffer, size_t len)
{
    if (input->type == CONTENT_TYPE_FILE)
    {
        return read(input->u.file.fd, buffer, len);
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
