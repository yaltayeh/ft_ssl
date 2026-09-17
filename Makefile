NAME = ft_ssl

CC = cc

CFLAGS = -Wall -Wextra -Werror

LDFLAGS = -lm

BUILD_DIR = build

SRCS =	main.c				\
		md5_hash.c			\
		sha256_hash.c		\
		define_functions.c	\
		content_input.c		\

OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

PHONY: all clean fclean re
