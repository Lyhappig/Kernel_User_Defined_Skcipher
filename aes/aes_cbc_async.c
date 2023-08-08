/* 
 * cryptosk.c
 * 
 */ 
#include <crypto/internal/skcipher.h> 
#include <linux/crypto.h> 
#include <linux/module.h> 
#include <linux/random.h> 
#include <linux/scatterlist.h> 
 
#define SYMMETRIC_KEY_LENGTH 16
#define CIPHER_BLOCK_SIZE 16 
 
struct tcrypt_result { 
    struct completion completion; 
    int err; 
}; 
 
struct skcipher_def { 
    struct scatterlist sg; 
    struct crypto_skcipher *tfm; 
    struct skcipher_request *req; 
    struct tcrypt_result result; 
    unsigned char *scratchpad;
    unsigned char *ciphertext; 
    unsigned char *ivdata; 
}; 
 
static struct skcipher_def sk;
 
static void test_skcipher_finish(struct skcipher_def *sk) 
{ 
    if (sk->tfm) 
        crypto_free_skcipher(sk->tfm); 
    if (sk->req) 
        skcipher_request_free(sk->req); 
    if (sk->ivdata) 
        kfree(sk->ivdata); 
    if (sk->scratchpad) 
        kfree(sk->scratchpad); 
    if (sk->ciphertext) 
        kfree(sk->ciphertext); 
} 

/**
 * 检查加密结果(成功/报错)
*/
static int test_skcipher_result(struct skcipher_def *sk, int rc) 
{ 
    switch (rc) { 
    case 0: 
        break; 
    case -EINPROGRESS || -EBUSY: 
        rc = wait_for_completion_interruptible(&sk->result.completion); 
        if (!rc && !sk->result.err) { 
            reinit_completion(&sk->result.completion); 
            break; 
        } 
        pr_info("skcipher encrypt returned with %d result %d\n", rc, 
                sk->result.err); 
        break; 
    default: 
        pr_info("skcipher encrypt returned with %d result %d\n", rc, 
                sk->result.err); 
        break; 
    }
	
    init_completion(&sk->result.completion); 
    return rc; 
} 

/**
 * 加密完成后的反馈函数
*/
static void test_skcipher_callback(struct crypto_async_request *req, int error) 
{ 
    struct tcrypt_result *result = req->data; 
 
    if (error == -EINPROGRESS) 
        return; 
 
    result->err = error; 
    complete(&result->completion); 
    pr_info("Encryption finished successfully\n");

#if 1
    /* decrypt data */
    memset((void*)sk.scratchpad, '-', CIPHER_BLOCK_SIZE); 
    int ret = crypto_skcipher_decrypt(sk.req); 
    ret = test_skcipher_result(&sk, ret); 
    if (ret)
        return;
 
    sg_copy_from_buffer(&sk.sg, 1, sk.scratchpad, CIPHER_BLOCK_SIZE);
#endif
}

 
static int test_skcipher_encrypt(unsigned char *plaintext, struct skcipher_def *sk) 
{ 
    int ret = -EFAULT;
    unsigned char key[SYMMETRIC_KEY_LENGTH]; 
 
    if (!sk->tfm) { 
		//为 Skcipher 分配密码句柄。返回的 crypto_skcipher 结构是后续 API 调用该 skcipher 时所需的密码句柄。
        sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0); 
        if (IS_ERR(sk->tfm)) { 
            pr_info("could not allocate skcipher handle\n"); 
            return PTR_ERR(sk->tfm); 
        } 
    } 
 
    if (!sk->req) {
		// 分配必须与 skcipher 加密和解密 API 调用一起使用的请求数据结构。在分配过程中，所提供的 skcipher 句柄注册到请求数据结构中。
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL); 
        if (!sk->req) { 
            pr_info("could not allocate skcipher request\n"); 
            ret = -ENOMEM; 
            goto out; 
        } 
    } 
	
	// 该函数允许设置密码操作完成后触发的回调函数。
	// 回调函数使用 skcipher_request 句柄注册，必须符合以下模板: void callback_function(struct crypto_async_request *req, int error)
    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG, 
                                  test_skcipher_callback, &sk->result); 
 
    /* clear the key */
    memset((void *)key, '\0', SYMMETRIC_KEY_LENGTH);
    /* random key */
    get_random_bytes(key, SYMMETRIC_KEY_LENGTH);
    print_hex_dump(KERN_DEBUG, "Key: ", DUMP_PREFIX_NONE, 16, 1, key, SYMMETRIC_KEY_LENGTH, false);
 
    /* AES 128 with given symmetric key */ 
    if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH)) { 
        pr_info("key could not be set\n"); 
        ret = -EAGAIN; 
        goto out;
    }
    print_hex_dump(KERN_DEBUG, "Plaintext: ", DUMP_PREFIX_NONE, 16, 1, plaintext, CIPHER_BLOCK_SIZE, true);
 
    if (!sk->ivdata) { 
        sk->ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
        if (!sk->ivdata) { 
            pr_info("could not allocate ivdata\n"); 
            goto out; 
        }
		// 获取随机的IV
        get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE);
        print_hex_dump(KERN_DEBUG, "IV: ", DUMP_PREFIX_NONE, 16, 1, sk->ivdata, CIPHER_BLOCK_SIZE, false);
    } 
 
    if (!sk->scratchpad) { 
        /* The text to be encrypted */ 
        sk->scratchpad = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
        if (!sk->scratchpad) { 
            pr_info("could not allocate scratchpad\n"); 
            goto out; 
        } 
    }

    if (!sk->ciphertext) {
        sk->ciphertext = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
        if (!sk->ciphertext) { 
            pr_info("could not allocate ciphertext\n"); 
            goto out; 
        } 
    }
    
    memcpy(sk->scratchpad, plaintext, CIPHER_BLOCK_SIZE);
 
    sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE); 
	// 加密时，源数据被视为明文，目标数据被视为密文。对于解密操作，源数据是密文，目标数据是明文。
    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, CIPHER_BLOCK_SIZE, 
                               sk->ivdata); 
    init_completion(&sk->result.completion); 

    /* encrypt data */ 
    ret = crypto_skcipher_encrypt(sk->req); 
    ret = test_skcipher_result(sk, ret); 
    if (ret) 
        goto out;
    sg_copy_to_buffer(&sk->sg, 1, sk->ciphertext, CIPHER_BLOCK_SIZE);
    print_hex_dump(KERN_DEBUG, "Ciphertext: ", DUMP_PREFIX_NONE, 16, 1, sk->ciphertext, CIPHER_BLOCK_SIZE, false);
    /* decrypt result */ 
    print_hex_dump(KERN_DEBUG, "Decrypt text: ", DUMP_PREFIX_NONE, 16, 1, sk.scratchpad, CIPHER_BLOCK_SIZE, true);
    pr_info("Decryption finished successfully\n");
out: 
    return ret; 
}
 
static int __init cryptoapi_init(void) 
{ 
 
    sk.tfm = NULL; 
    sk.req = NULL; 
    sk.scratchpad = NULL; 
    sk.ciphertext = NULL; 
    sk.ivdata = NULL; 
 
    test_skcipher_encrypt("abcdefghijklmnop", &sk); 
    return 0; 
} 
 
static void __exit cryptoapi_exit(void) 
{ 
    test_skcipher_finish(&sk); 
} 
 
module_init(cryptoapi_init); 
module_exit(cryptoapi_exit); 

MODULE_DESCRIPTION("AES-CBC async Encryption"); 
MODULE_LICENSE("GPL");