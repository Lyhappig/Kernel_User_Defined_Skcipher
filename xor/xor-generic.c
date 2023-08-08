#include <linux/types.h>
#include <linux/crypto.h> 
#include <linux/module.h> 
#include <linux/init.h>
#define XOR_BLOCK_SIZE	16
#define XOR_KEY_SIZE	16
#define XOR_ROUNDS		16
#define XOR_IV_SIZE		16


struct crypto_xor_ctx {
	u8 key_enc[XOR_KEY_SIZE];
	u8 key_dec[XOR_KEY_SIZE];
	u32 key_len;
};


int xor_expandkey(struct crypto_xor_ctx *ctx, const u8 *in_key,
		  unsigned int key_len)
{
	u32 i;
	if(key_len != 16) {
		return -EINVAL;
	}
	ctx->key_len = key_len;
	for(i = 0; i < key_len; i++) {
		ctx->key_enc[i] = in_key[i];
		ctx->key_dec[i] = in_key[i];
	}
	return 0;
}


int crypto_xor_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	struct crypto_xor_ctx *ctx = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;
	int ret;

	ret = xor_expandkey(ctx, in_key, key_len);
	if (!ret)
		return 0;

	*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
	return -EINVAL;
}
EXPORT_SYMBOL(crypto_xor_set_key);

static void crypto_xor_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in) 
{
	const struct crypto_xor_ctx *ctx = crypto_tfm_ctx(tfm);
	int key_len = ctx->key_len;
	const u8 *key = ctx->key_enc;
	u32 i;

	for(i = 0; i < XOR_ROUNDS; i++) {
		out[i] = in[i] ^ key[i];
	}
}
EXPORT_SYMBOL(crypto_xor_encrypt);

static void crypto_xor_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in) 
{
	const struct crypto_xor_ctx *ctx = crypto_tfm_ctx(tfm);
	int key_len = ctx->key_len;
	const u8 *key = ctx->key_enc;
	u32 i;

	for(i = 0; i < XOR_ROUNDS; i++) {
		out[i] = in[i] ^ key[i];
	}
}
EXPORT_SYMBOL(crypto_xor_decrypt);


static struct crypto_alg xor_alg = {
	.cra_name		=	"xor",
	.cra_driver_name	=	"xor-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	XOR_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_xor_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	=	XOR_KEY_SIZE,
			.cia_max_keysize	=	XOR_KEY_SIZE,
			.cia_setkey		=	crypto_xor_set_key,
			.cia_encrypt		=	crypto_xor_encrypt,
			.cia_decrypt		=	crypto_xor_decrypt
		}
	}
};


static int __init xor_init(void)
{
    return crypto_register_alg(&xor_alg);
}

static void __exit xor_exit(void)
{
    crypto_unregister_alg(&xor_alg);
}

subsys_initcall(xor_init);
module_exit(xor_exit);
 
MODULE_AUTHOR("Happig yuhaolian@hust.edu.cn");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xor Encryption");