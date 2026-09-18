#include "ft_ssl.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "hash_functions/hash_functions.h"

static void print_usage(void)
{
    err_str("usage: ft_ssl command [flags] [file/string]\n");
}

static void print_invalid_command(const char *command)
{
    const struct hash_function **list = get_hash_function_list();

    err_str("ft_ssl: Error: '");
    err_str(command);
    err_str("' is an invalid command.\n\nCommands:\n");
    for (size_t i = 0; list[i] != NULL; i++)
    {
        err_str(list[i]->name);
        err_str("\n");
    }
    err_str("\nFlags:\n-p -q -r -s\n");
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_usage();
        return (1);
    }

    struct hash_function *hash_func = get_hash_function_by_name(argv[1]);
    if (hash_func)
        return (run_hash(hash_func, argv[1], argc - 2, argv + 2));

    print_invalid_command(argv[1]);

    return (1);
}
