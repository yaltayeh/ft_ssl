#include "ft_ssl.h"
#include "ssl_function.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

static void print_usage(void)
{
    err_str("usage: ft_ssl command [flags] [file/string]\n");
}

static void print_invalid_command(const char *command)
{
    const struct ssl_functions_group **list = get_ssl_group_list();

    err_str("ft_ssl: Error: '");
    err_str(command);
    err_str("' is an invalid command.\n\n");
    for (size_t i = 0; list[i]; i++)
    {
        err_str(list[i]->title);
        err_str(":\n");
        for (size_t j = 0; list[i]->functions && list[i]->functions[j]; j++)
        {
            err_str(list[i]->functions[j]->name);
            err_str("\n");
        }
        err_str("\n");
    }
}

int main(int argc, char **argv)
{
    const struct ssl_functions_group *group = NULL;
    const struct ssl_function        *func  = NULL;

    if (argc < 2)
    {
        print_usage();
        return (1);
    }

    if (get_function_by_name(argv[1], &group, &func))
    {
        return(group->run(func, argc - 2, argv + 2));
    }
    
    print_invalid_command(argv[1]);

    return (1);
}
