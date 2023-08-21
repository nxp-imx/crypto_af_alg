/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023 NXP
 *
 */
#ifndef __APP_H
#define __APP_H

#include <stdint.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define CAAM_KEYGEN_APP		"/usr/bin/caam-keygen"
#define CAAM_KEYGEN_IMPORT	"import"
#define KEY_LOCATION		"/data/caam/"
#define KEY_NAME		"black_key"
#define IV_LEN			16
#define BLOCK_SIZE		16
#define MAX_ARG			11
#define MAX_PERF_ARG		8
#define FAILURE			-1
#define SUCCESS			0
#define NUM_BLOCK_SIZE		8
#define SEC_TO_MICROSEC		1000000LL
#define KB			1000u
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof(a[0]))

/*
 * skcipher_vec: structure to describe a symmetric cipher input
 * @key:	 Pointer to key
 * @iv:		 Pointer to iv.
 * @ptext:	 Pointer to plaintext
 * @ctext:	 Pointer to ciphertext
 * @klen:	 Length of @key in bytes
 * @len:	 Length of @ptext and @ctext in bytes
 */
struct skcipher_vec {
	char *key;
	char *iv;
	char *ptext;
	char *ctext;
	unsigned int klen;
	unsigned int len;
};

struct aead_vec {
	char *key;
	char *iv;
	char *ptext;		// ptext: assoc data + plaintext
	char *ctext;		// ctext: assoc data + ciphertext + auth tag
	unsigned int klen;
	unsigned int assoc_len;	// associated data len
	unsigned int plen;	// assoc_len + plaintext
	unsigned int clen;	// assoc_len + ciphetext len + Auth Tag len
};

struct hash_vec {
	char *plaintext;
	char *digest;
	unsigned int psize;
	unsigned int hashlen;
};

/* per block size performance stats*/
struct perf_stat {
	uint32_t ops;
	uint32_t block_size;
	double ops_time;	/* total time of ops in microseconds */
	double t_per_op;	/* time per op in microsecond */
	double cpu_time;
};

int get_fd_socket(struct sockaddr_alg sa);
int sk_ecb_msg(int tfmfd, const struct skcipher_vec *vec, struct msghdr *msg,
	       struct iovec *iov, bool enc);
int sk_cbc_msg(int tfmfd, const struct skcipher_vec *vec, struct msghdr *msg,
	       struct iovec *iov, bool enc);
int run_crypt(int opfd, struct msghdr *msg, char *output, unsigned int len);
int run_perf_test(int argc, char *argv[]);
int aead_msg(int tfmfd, const struct aead_vec *vec, struct msghdr *msg,
	     struct iovec *iov, bool enc);
int hash_crypt(int opfd, char *plaintext, unsigned int psize, char *output,
	       unsigned int hashlen);
void print_help(char *app);
#endif
