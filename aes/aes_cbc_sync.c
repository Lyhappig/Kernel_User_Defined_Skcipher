#include <linux/module.h>
#include <linux/crypto.h> 
#include <linux/random.h> 
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

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
    sg_copy_to_buffer(&mgc->sg, 1, ciphertext, datasize);
    print_hex_dump(KERN_DEBUG, "ciphertext: ", DUMP_PREFIX_NONE, 16, 1, ciphertext, datasize, false);
    // actual decrypt
    memset(plaintext, 0, 1500);
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
    if (!crypto_has_skcipher("cbc(aes)", 0, 0)) {
        pr_err("skcipher not found\n");
        err = -EINVAL;
        return err;
    }

    mgc->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(mgc->tfm)) {
        pr_err("impossible to allocate skcipher\n");
        return PTR_ERR(mgc->tfm);
    }

    memset(mgc->key, 0, 16);
    mgc->keysize = 16;

    memcpy(mgc->key,"1234567890123456", 16);
    print_hex_dump(KERN_DEBUG, "key: ", DUMP_PREFIX_NONE, 16, 1, mgc->key, mgc->keysize, false);

    /* Default function to set the key for the symetric key cipher */
    crypto_skcipher_setkey(mgc->tfm, mgc->key, mgc->keysize);

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

static int __init my_crypt_init(void)
{
    int err = 0;
    sk.iv = NULL;
    sk.tfm = NULL;
    sk.req = NULL;
    err = my_crypt_test("abcdefghijklmnop", &sk);
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
 
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AES-CBC sync Encryption");

