#include <linux/module.h>
#include <linux/crypto.h> 
#include <linux/random.h> 
#include <crypto/skcipher.h>
#include <crypto/internal/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/err.h>

struct my_crypto_vars {
    u8 *iv;
    size_t ivsize;
    u8 key[16];
    size_t keysize;
    struct crypto_skcipher *tfm;
    struct scatterlist sg;
    struct skcipher_request *req;
};

struct my_crypto_vars sk;

static int my_crypt_encrypt(struct my_crypto_vars *mgc, u8 *data, size_t datasize)
{
    int err = 0;
    char plaintext[1500] = {0};
    char ciphertext[1500] = {0};
    // init encrypt
    memcpy(plaintext, data, datasize);
    sg_init_one(&mgc->sg, plaintext, datasize);
    skcipher_request_set_crypt(mgc->req, &mgc->sg, &mgc->sg, datasize, mgc->iv);
    // actual encrypt
    err = crypto_skcipher_encrypt(mgc->req);
    if (err) {
        pr_info("could not encrypt data\n");
        return err;
    }
    pr_debug("encrypt success");

    sg_copy_to_buffer(&mgc->sg, 1, ciphertext, datasize);
    print_hex_dump(KERN_DEBUG, "eciphertext: ", DUMP_PREFIX_NONE, 16, 1, ciphertext, datasize, false);
    // actual decrypt
    memset(plaintext, 0, 1500);
    // sg_init_one(&mgc->sg, ciphertext, datasize);
    err = crypto_skcipher_decrypt(mgc->req);
    if (err) {
        pr_info("could not decrypt data\n");
        return err;
    }
    sg_copy_to_buffer(&mgc->sg, 1, plaintext, datasize);
    print_hex_dump(KERN_DEBUG, "decrypt text: ", DUMP_PREFIX_NONE, 16, 1, plaintext, datasize, true);
    return 0;
}

static int my_crypt_test(unsigned char *plaintext, struct my_crypto_vars *mgc) {
    int err = 0;
    /* Check the existence of the cipher in the kernel (it might be a
    * module and it isn’t loaded. */
    if (!crypto_has_skcipher("cbc(xor)", 0, 0)) {
        pr_err("skcipher not found\n");
        err = -EINVAL;
        return err;
    }

    mgc->tfm = crypto_alloc_skcipher("cbc(xor)", 0, 0);
    if (IS_ERR(mgc->tfm)) {
        pr_err("impossible to allocate skcipher\n");
        return PTR_ERR(mgc->tfm);
    }

    memset(mgc->key, 0, 16);
    mgc->keysize = 16;

    memcpy(mgc->key,"0123456789ABCDEF", 16);
    
    /* Default function to set the key for the symetric key cipher */
    crypto_skcipher_setkey(mgc->tfm, mgc->key, mgc->keysize);

    print_hex_dump(KERN_DEBUG, "key: ", DUMP_PREFIX_NONE, 16, 1, mgc->key, mgc->keysize, false);

    if (err) {
		pr_err("fail setting key for transformation: %d\n", err);
		return err;
    }

    mgc->ivsize = crypto_skcipher_ivsize(mgc->tfm);
    mgc->iv = kmalloc(mgc->ivsize, GFP_KERNEL);

    if (!mgc->iv) {
		pr_err("could not allocate iv vector\n");
		err = -ENOMEM;
		return err;
    }
    get_random_bytes(mgc->iv, mgc->ivsize);
    print_hex_dump(KERN_DEBUG, "iv: ", DUMP_PREFIX_NONE, 16, 1, mgc->iv, mgc->ivsize, false);
    mgc->req = skcipher_request_alloc(mgc->tfm, GFP_KERNEL);

    if (!mgc->req) {
		pr_info("impossible to allocate skcipher request\n");
		err = -ENOMEM;
		return err;
    }
    print_hex_dump(KERN_DEBUG, "plaintext: ", DUMP_PREFIX_NONE, 16, 1, plaintext, 16, true);

    err = my_crypt_encrypt(mgc, plaintext, 16);
    if(err < 0) {
        return err;
    }
    return 0;
}


static void single_test(void) {
	struct crypto_skcipher *tfm = crypto_alloc_skcipher("cbc(xor)", 0, 0);
	if (IS_ERR(tfm) || tfm == NULL) {
        pr_info("impossible to allocate skcipher\n");
        return PTR_ERR(tfm);
    }
	u8 in[16], out[16], key[16];
	memcpy(in,"0123456789ABCDEF", 16);
	memcpy(key,"0123456789ABCDEF", 16);

    if(tfm->setkey == NULL) {
        pr_info("no setkey func in crypto_skcipher");
        return;
    }

    struct crypto_cipher *cc = skcipher_cipher_simple(tfm);
    // kong !!!
    if(cc == NULL) {
        pr_info("crypto_cipher is NULL");
        return;
    }

    struct cipher_tfm *test = crypto_cipher_crt(cc);

    if(test == NULL) {
        pr_info("crypto_tfm is NULL");
        return;
    }

    if(test->cit_encrypt_one == NULL) {
        pr_info("crypto_tfm setkey func in crypto_skcipher");
        return;
    }

	// u32 err = crypto_skcipher_setkey(tfm, key, XOR_KEY_SIZE);
	// if (err < 0) {
	// 	pr_info("set key error");
	// 	return;
	// }
    // crypto_cipher_encrypt_one(skcipher_cipher_simple(tfm), out, in);
	// print_hex_dump(KERN_DEBUG, "cipher: ", DUMP_PREFIX_NONE, 16, 1, out, XOR_BLOCK_SIZE, false);

    pr_info("test successed");
}

static int __init my_crypt_init(void)
{
    int err = 0;
    sk.iv = NULL;
    sk.tfm = NULL;
    sk.req = NULL;
    err = my_crypt_test("0123456789ABCDEF", &sk);
    return err;
}

static void __exit my_crypt_exit(void)
{
    skcipher_request_free(sk.req);
    crypto_free_skcipher(sk.tfm);
    if (sk.iv) kfree(sk.iv);
}

module_init(my_crypt_init);
module_exit(my_crypt_exit);

MODULE_AUTHOR("Happig yuhaolian@hust.edu.cn");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test xor-cbc Encryption");

