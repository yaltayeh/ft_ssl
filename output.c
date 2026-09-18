#include "ft_ssl.h"
#include <unistd.h>

/*
** All program output goes through write(2) rather than stdio. Besides keeping
** to the subject's allowed-function list, it guarantees that the stdout lines
** and the stderr error lines stay interleaved in argv order: a buffered stdout
** would flush after the unbuffered stderr whenever stdout is a pipe or a file.
*/

static void fd_write(int fd, const char *data, size_t len)
{
    size_t written = 0;

    while (written < len)
    {
        ssize_t ret = write(fd, data + written, len - written);
        if (ret <= 0)
            return;
        written += (size_t)ret;
    }
}

size_t ft_strlen(const char *s)
{
    size_t len = 0;

    while (s && s[len])
        len++;
    return (len);
}

void out_bytes(const char *data, size_t len)
{
    fd_write(STDOUT_FILENO, data, len);
}

void out_str(const char *s)
{
    fd_write(STDOUT_FILENO, s, ft_strlen(s));
}

void out_hex(const uint8_t *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    char hex[2];

    for (size_t i = 0; i < len; i++)
    {
        hex[0] = digits[(data[i] >> 4) & 0x0f];
        hex[1] = digits[data[i] & 0x0f];
        fd_write(STDOUT_FILENO, hex, 2);
    }
}

void err_str(const char *s)
{
    fd_write(STDERR_FILENO, s, ft_strlen(s));
}
