## 操作系统

CentOS8 Linux 5.4.250-1.el8.elrepo.x86_64

## 结构

```
|--aes
	|--aes_cbc_async.c
	|--aes_cbc_sync.c
	|--Makefile
	|--usp_cbc.c
|--xor
	|--create_xor_cbc.c
	|--Makefile
	|--test_cbc_xor.c
	|--test_xor.c
	|--usp_xor.c
	|--xor-generic.c
```

### aes 目录

- aes_cbc_async.c: 测试异步的AES-CBC算法的内核模块

- aes_cbc_sync.c: 测试同步的AES-CBC算法的内核模块

- Makefile: 编译内核模块

- usp_cbc.c: 用户态调用 AES-CBC 内核接口

### xor 目录

- create_xor_cbc.c: 由内核动态创建模板 (cbc,ecb,xts...等) 和加密算法 (crypto_alg) 的实例，作为内核模块调用

- test_cbc_xor.c: 测试同步的XOR-CBC算法的内核模块

- test_xor.c: 测试单一分组的XOR算法的内核模块

- Makefile: 编译内核模块

- usp_xor.c: 用户态调用 XOR-CBC 内核接口

- xor-generic.c: XOR 加密算法的内核模块


## 运行

内核模块需要：

```bash
make
insmod xxx.ko
```

或者将 `xxx.ko` 移动到 `/lib/modules/$(uname -r)` 下，然后：

```bash
depmod
modprobe
```

## 注意事项

能够由内核动态创建算法和模板的实例，必须要在 xor-generic 模块中的加解密和设置密钥函数下，提供开放给内核调用的函数接口：

```c
EXPORT_SYMBOL(crypto_xor_decrypt);
```

## 参考

Linux kernel v5.4：

`/linux-5.4/crypto/aes_generic.c`

`/linux-5.4/crypto/sm4_generic.c`