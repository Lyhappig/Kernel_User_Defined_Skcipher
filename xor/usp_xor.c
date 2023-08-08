/**
 * 通过 AF_ALG 实现用户态调用内核加密接口，实现自定义 xor 分组加密
*/
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int main(void) {
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(xor)"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4)] = {0};
	char buf[16];

	struct iovec iov;
	int i;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

  	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
	// 06a9214036b8a15b512e03d534120006
	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY,
			"\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
			"\x51\x2e\x03\xd5\x34\x12\x00\x06",
			16);

	opfd = accept(tfmfd, NULL, 0);

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

	iov.iov_base = "Single block msg";
	iov.iov_len = 16;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(opfd, &msg, 0);
	read(opfd, buf, 16);

	for (i = 0; i < 16; i++) {
		printf("%02x ", (unsigned char)buf[i]);
	}
	printf("\n");

	close(opfd);
	close(tfmfd);
	return 0;
}