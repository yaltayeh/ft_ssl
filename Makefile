NAME = ft_ssl

CC = cc

CFLAGS = -Wall -Wextra -Werror

LDFLAGS = -lm

BUILD_DIR = build

SRCS =	main.c						\
	content_input.c					\
	utils.c							\
	output.c						\
	hash_functions/md5_hash.c		\
	hash_functions/sha256_hash.c	\
	hash_functions/run_hash.c		\
	hash_functions/hash_functions.c

OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re