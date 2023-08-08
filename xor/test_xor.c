/* 
 * test_xor.c 
 * 测试 xor 的分组加密
 */ 
#include <linux/crypto.h> 
#include <linux/module.h> 
#include <linux/random.h>
#include <linux/types.h>
 
#define CIPHER_KEY_LENGTH 16
#define CIPHER_BLOCK_SIZE 16 

struct xor_ctx { 
    struct crypto_cipher *tfm;
    u8 *plaintext;
    u8 *ciphertext;
}; 

static struct xor_ctx ctx;

static void test_xor_cleanup(struct xor_ctx *ctx) 
{ 
    if (ctx->tfm)
        crypto_free_cipher(ctx->tfm);
    if (ctx->plaintext)
    	kfree(ctx->plaintext);
    if (ctx->ciphertext)
    	kfree(ctx->ciphertext);
} 

static int alloc_init(struct xor_ctx *ctx) {
    if(!crypto_has_cipher("xor-generic", 0, 0)) {
        pr_info("could not find cipher handle\n");
        return -1;
    }
 
    if (!ctx->tfm) {
        ctx->tfm = crypto_alloc_cipher("xor-generic", 0, 0);
        if (IS_ERR(ctx->tfm)) {
            pr_info("could not allocate cipher handle\n"); 
            return PTR_ERR(ctx->tfm); 
        }
    }

    if (!ctx->plaintext) { 
        /* The text to be encrypted */ 
        ctx->plaintext = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
        if (!ctx->plaintext) { 
            pr_info("could not allocate scratchpad\n"); 
            return -1;
        } 
    }

    if (!ctx->ciphertext) {
        ctx->ciphertext = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
		if (!ctx->ciphertext) { 
            pr_info("could not allocate ciphertext\n"); 
            return -1;
        } 
    }
    
    return 0;
}

static void contrast(u8 *key, u8 *data) {
    u32 i;
    u8 p[CIPHER_BLOCK_SIZE];
    memcpy(p, data, CIPHER_BLOCK_SIZE);
    for(i = 0; i < CIPHER_BLOCK_SIZE; i++) {
        p[i] = p[i] ^ key[i];
    }
    print_hex_dump(KERN_DEBUG, "Contrast: ", DUMP_PREFIX_NONE, 16, 1, p, CIPHER_BLOCK_SIZE, false);
}

static int check_empty(u8 *data) {
    u32 i;
    for(i = 0; i < CIPHER_BLOCK_SIZE; i++) {
        if(data[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int test_xor_encrypt(unsigned char *plaintext, struct xor_ctx *ctx) 
{ 
    unsigned char key[CIPHER_KEY_LENGTH];

    if(!crypto_has_cipher("xor-generic", 0, 0)) {
        pr_info("could not find cipher handle\n");
        return -ENODATA;
    }

    if (alloc_init(ctx) < 0) {
        goto out;
    }
 
    /* clear the key */
    memset((void *)key, '\0', CIPHER_KEY_LENGTH);
    /* random key */
    get_random_bytes(key, CIPHER_KEY_LENGTH);
    print_hex_dump(KERN_DEBUG, "Key: ", DUMP_PREFIX_NONE, 16, 1, key, CIPHER_KEY_LENGTH, false);
 
    /* xor 128 with random key */ 
    if (crypto_cipher_setkey(ctx->tfm, key, CIPHER_KEY_LENGTH)) { 
        pr_info("key could not be set\n");
        return -EAGAIN; 
    }
    print_hex_dump(KERN_DEBUG, "Plaintext: ", DUMP_PREFIX_NONE, 16, 1, plaintext, CIPHER_BLOCK_SIZE, true);
    /* Contrast encryption*/
    contrast(key, ctx->plaintext);
    /* encrypt data */ 
    memset(ctx->ciphertext, 0, sizeof(ctx->ciphertext));
    crypto_cipher_encrypt_one(ctx->tfm, ctx->ciphertext, ctx->plaintext);
    if (check_empty(ctx->ciphertext)) {
        pr_info("could not encrypt data\n");
        goto out;
    }
        
    print_hex_dump(KERN_DEBUG, "Ciphertext: ", DUMP_PREFIX_NONE, 16, 1, ctx->ciphertext, CIPHER_BLOCK_SIZE, false);
    pr_info("Encryption finished successful\n");

    /* decrypt data */
    memset(ctx->plaintext, 0, sizeof(ctx->plaintext));
    crypto_cipher_decrypt_one(ctx->tfm, ctx->plaintext, ctx->ciphertext);
    if (check_empty(ctx->plaintext)) {
        pr_info("could not decrypt data\n");
        goto out;
    }
    print_hex_dump(KERN_DEBUG, "decrypt text: ", DUMP_PREFIX_NONE, 16, 1, ctx->plaintext, CIPHER_BLOCK_SIZE, true);
    pr_info("Decryption finished successfully\n");
    return 0;
out: 
    return -EFAULT;
}
 
static int __init test_xor_init(void) 
{ 
	return test_xor_encrypt("abcdefghijklmnop", &ctx); 
} 
 
static void __exit test_xor_exit(void) 
{ 
	test_xor_cleanup(&ctx);
}
 
module_init(test_xor_init);
module_exit(test_xor_exit);

MODULE_AUTHOR("Happig yuhaolian@hust.edu.cn");
MODULE_DESCRIPTION("Test xor algorithm"); 
MODULE_LICENSE("GPL");