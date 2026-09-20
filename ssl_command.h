struct ssl_function
{
	int kind;
	int (*run)(const void *impl, const char *command, int optc, char **optv);
};

struct ssl_command
{
	const char *name;
	const char *display_name;
	const struct ssl_function *func;
	const void *impl;
};
