#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/err.h>

static int __init create_xor_cbc_init(void)
{
    int err = 0;
    if (!crypto_has_skcipher("cbc(xor)", 0, 0)) {
        pr_err("skcipher not found\n");
        err = -EINVAL;
        return err;
    }
    return err;
}

static void __exit create_xor_cbc_exit(void)
{

}

module_init(create_xor_cbc_init);
module_exit(create_xor_cbc_exit);

MODULE_AUTHOR("Happig yuhaolian@hust.edu.cn");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("create xor-cbc");

