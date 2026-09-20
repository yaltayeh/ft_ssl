#ifndef SSL_FUNCTION_H
#define SSL_FUNCTION_H

struct ssl_function
{
	const char *name;
	const char *display_name;
};

struct ssl_functions_group
{
	const char *title;
	const struct ssl_function **functions;

	int (*run)(const struct ssl_function *func,
				int optc,
				char **optv);
};

const struct ssl_functions_group **get_ssl_group_list(void);

int get_function_by_name(const char *name,
                        const struct ssl_functions_group **group_ptr,
                        const struct ssl_function **func_ptr);

#endif /* SSL_FUNCTION_H */
