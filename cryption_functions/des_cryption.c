#include "cryption_functions.h"
#include "../ft_ssl.h"

struct des_state
{
	uint64_t key;
	uint64_t subkeys[16];
	uint64_t left, right;
};

static void des_init(struct cryption_context *ctx)
{
	struct des_state *state = ctx->state;

	state->left = rightrotate_64(state->key, 28) & 0xfffffff;
	state->right = state->key & 0xfffffff;

}

const struct cryption_function des_cryption_function = {
	.func.name			= "des",
	.func.display_name	= "DES",
	.init				= des_init,
	.state_size			= sizeof(struct des_state),
	.block_size			= 16,
};