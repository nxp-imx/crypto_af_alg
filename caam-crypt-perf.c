// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "aes_cbc.h"
#include "aes_ecb.h"
#include "aes_gcm.h"
#include "sha_256.h"
#include "sha_384.h"
#include <ctype.h>
#include <time.h>

struct skcipher_suite {
	const struct skcipher_vec *vecs;
	unsigned int count;
};

struct aead_suite {
	const struct aead_vec *vecs;
	unsigned int count;
};

struct hash_suite {
	const struct hash_vec *vecs;
	unsigned int count;
};

struct alg_test {
	const char *alg_name;
	const char *generic_name;
	int (*func)(const struct alg_test *algtest, bool enc, uint32_t seconds);
	union {
		struct skcipher_suite skcipher;
		struct aead_suite aead;
		struct hash_suite hash;
	} suite;
};

void hexdump(uint8_t buf[], uint32_t size)
{
	int i = 0;

	for (i = 0; i < size; i++) {
		if ((i != 0) && (i % 16 == 0))
			printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

/* t_per_op is in microseconds. */
double kb_per_sec(size_t block_size, double t_per_op)
{
	if (t_per_op == 0)
		return 0;

	return ((double)SEC_TO_MICROSEC / t_per_op) * ((double)block_size / (double)KB);
}

void print_performance_stat(struct perf_stat *stat, const char *algo, bool enc, unsigned int count)
{
	struct perf_stat *temp = stat;

	if (!stat || !algo) {
		printf("Invalid perf_data or algo pointer\n");
		return;
	}

	printf("\nThe numbers are in 1000 per second.\n");
	printf("type\t\t");
	for (int i = 0; i < count; i++) {
		printf("%d bytes         ", temp->block_size);
		temp++;
	}

	temp = stat;
	printf("\n%-9s\t", algo);
	for (int i = 0; i < count; i++) {
		printf("%0.2lfk          ", kb_per_sec(temp->block_size, temp->t_per_op));
		temp++;
	}
	printf("\n");
}

static void time_diff(struct timespec *res,
		      const struct timespec *start,
		      const struct timespec *end)
{
	res->tv_sec = end->tv_sec - start->tv_sec;
	res->tv_nsec = end->tv_nsec - start->tv_nsec;
	if (res->tv_nsec < 0) {
		res->tv_sec--;
		res->tv_nsec += 1000000000;
	}
}

void update_performance_stats(struct perf_stat *stat, uint32_t vec_len,
			      struct timespec *start,
			      struct timespec *end)
{
	struct timespec diff;
	double diff_microsec, delta, delta_per_op;

	time_diff(&diff, start, end);
	diff_microsec = diff.tv_sec * 1000000 + (diff.tv_nsec * 0.001);

	stat->ops_time += diff_microsec;
	stat->ops++;

	delta = diff_microsec - stat->t_per_op;
	delta_per_op = delta / (double)stat->ops;

	stat->t_per_op += delta_per_op;
	stat->block_size = vec_len;
}

static int test_aead_vec(const struct aead_vec *vec,
			 struct perf_stat *perf,
			 const char *generic_name,
			 bool enc, uint32_t seconds)
{
	int sock_fd = 0, opfd = 0, ret = 0, outlen = 0;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(16) + CMSG_SPACE(4)] = {0};
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf)
	};
	struct iovec iov;
	struct timespec start = { }, end = { };
	uint32_t microseconds = seconds * SEC_TO_MICROSEC;
	char *out;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
	};

	memcpy(sa.salg_name, generic_name, strlen(generic_name)+1);

	sock_fd = get_fd_socket(sa);
	if (sock_fd < 0)
		return -1;

	ret = aead_msg(sock_fd, vec, &msg, &iov, enc);
	if (ret < 0)
		goto fd_close;

	opfd = accept(sock_fd, NULL, 0);
	if (opfd < 0) {
		printf("Failed to open connection for the socket\n");
		ret = -EBADF;
		goto fd_close;
	}

	/*
	 * AEAD enc out: assoc data || ciphertext || authentication tag
	 * AEAD enc out length: clen -> assoc_len + ciphertext len + auth tag len
	 *
	 * AEAD dec out: assoc data || plaintext
	 * AEAD dec out length: plen -> assoc_len + plaintext len
	 */
	outlen = enc ? vec->clen : vec->plen;
	out = calloc(outlen, sizeof(char));
	if (!out) {
		ret = -ENOMEM;
		goto opfd_close;
	}

	perf->ops_time = 0;

	/* check if the time for running the crypto operation completed */
	while (perf->ops_time < microseconds) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		ret = run_crypt(opfd, &msg, out, outlen);
		if (ret)
			goto exit;

		clock_gettime(CLOCK_MONOTONIC_RAW, &end);

		/* update performance statistics */
		update_performance_stats(perf, vec->plen - vec->assoc_len, &start, &end);
	}

	if (memcmp(out, enc ? vec->ctext : vec->ptext, outlen)) {
		printf("Encrypted/Decrypted data doesn't match\n");
		hexdump((uint8_t *)out, outlen);
	}

exit:
	free(out);
opfd_close:
	close(opfd);
fd_close:
	close(sock_fd);
	return ret;
}

static int aead_test(const struct alg_test *algtest, bool enc, uint32_t seconds)
{
	const struct aead_suite *aead = &algtest->suite.aead;
	struct perf_stat *perf_stat_arr;
	unsigned int i;
	int ret = 0;

	perf_stat_arr = malloc(aead->count * sizeof(struct perf_stat));
	if (!perf_stat_arr)
		return -ENOMEM;

	for (i = 0; i < aead->count; i++) {
		printf("Doing %s for %ds on %d size blocks: ",
			algtest->alg_name, seconds,
			aead->vecs[i].plen - aead->vecs[i].assoc_len);

		ret = test_aead_vec(&aead->vecs[i],
				    &perf_stat_arr[i],
				    algtest->generic_name,
				    enc, seconds);
		if (ret)
			goto exit;

		printf("%d ops (%.4lfus/op)\n",
			perf_stat_arr[i].ops,
			perf_stat_arr[i].t_per_op);
	}

	print_performance_stat(perf_stat_arr, algtest->alg_name, enc, aead->count);

exit:
	free(perf_stat_arr);
	return ret;
}

static int test_skcipher_ecb_vec(const struct skcipher_vec *vec,
				 struct perf_stat *perf,
				 const char *generic_name,
				 bool enc, uint32_t seconds)
{
	int sock_fd = 0, opfd = 0, ret = 0;
	char cbuf[CMSG_SPACE(4)] = {0};
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf)
	};
	struct iovec iov;
	struct timespec start = { }, end = { };
	uint32_t microseconds = seconds * SEC_TO_MICROSEC;
	char *out;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};

	memcpy(sa.salg_name, generic_name, strlen(generic_name)+1);

	sock_fd = get_fd_socket(sa);
	if (sock_fd < 0)
		return -1;

	ret = sk_ecb_msg(sock_fd, vec, &msg, &iov, enc);
	if (ret < 0)
		goto fd_close;

	opfd = accept(sock_fd, NULL, 0);
	if (opfd < 0) {
		printf("Failed to open connection for the socket\n");
		ret = -EBADF;
		goto fd_close;
	}

	out = calloc(vec->len, sizeof(char));
	if (!out) {
		ret = -ENOMEM;
		goto opfd_close;
	}

	perf->ops_time = 0;

	/* check if the time for running the crypto operation completed */
	while (perf->ops_time < microseconds) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		ret = run_crypt(opfd, &msg, out, vec->len);
		if (ret)
			goto exit;

		clock_gettime(CLOCK_MONOTONIC_RAW, &end);

		/* update performance statistics */
		update_performance_stats(perf, vec->len, &start, &end);
	}

	if (memcmp(out, enc ? vec->ctext : vec->ptext, vec->len)) {
		printf("Encrypted/Decrypted data doesn't match\n");
		hexdump((uint8_t *)out, vec->len);
	}

exit:
	free(out);
opfd_close:
	close(opfd);
fd_close:
	close(sock_fd);
	return ret;
}

static int test_skcipher_cbc_vec(const struct skcipher_vec *vec,
				 struct perf_stat *perf,
				 const char *generic_name,
				 bool enc, uint32_t seconds)
{
	int sock_fd = 0, opfd = 0, ret = 0;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf)
	};
	struct iovec iov;
	struct timespec start = { }, end = { };
	uint32_t microseconds = seconds * SEC_TO_MICROSEC;
	char *out;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};

	memcpy(sa.salg_name, generic_name, strlen(generic_name)+1);

	sock_fd = get_fd_socket(sa);
	if (sock_fd < 0)
		return -1;

	ret = sk_cbc_msg(sock_fd, vec, &msg, &iov, enc);
	if (ret < 0)
		goto fd_close;

	opfd = accept(sock_fd, NULL, 0);
	if (opfd < 0) {
		printf("Failed to open connection for the socket\n");
		ret = -EBADF;
		goto fd_close;
	}

	out = calloc(vec->len, sizeof(char));
	if (!out) {
		ret = -ENOMEM;
		goto opfd_close;
	}

	perf->ops_time = 0;

	/* check if the time for running the crypto operation completed */
	while (perf->ops_time < microseconds) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		ret = run_crypt(opfd, &msg, out, vec->len);
		if (ret)
			goto exit;

		clock_gettime(CLOCK_MONOTONIC_RAW, &end);

		/* update performance statistics */
		update_performance_stats(perf, vec->len, &start, &end);
	}

	if (memcmp(out, enc ? vec->ctext : vec->ptext, vec->len)) {
		printf("Encrypted/Decrypted data doesn't match\n");
		hexdump((uint8_t *)out, vec->len);
	}

exit:
	free(out);
opfd_close:
	close(opfd);
fd_close:
	close(sock_fd);
	return ret;
}

static int skcipher_test(const struct alg_test *algtest, bool enc, uint32_t seconds)
{
	const struct skcipher_suite *skcipher = &algtest->suite.skcipher;
	struct perf_stat *perf_stat_arr;
	unsigned int i;
	int ret = 0;

	perf_stat_arr = malloc(skcipher->count * sizeof(struct perf_stat));
	if (!perf_stat_arr)
		return -ENOMEM;

	for (i = 0; i < skcipher->count; i++) {
		printf("Doing %s for %ds on %d size blocks: ",
			algtest->alg_name, seconds,
			skcipher->vecs[i].len);

		if (!strcmp(algtest->generic_name, "cbc(aes)"))
			ret = test_skcipher_cbc_vec(&skcipher->vecs[i],
						    &perf_stat_arr[i],
						    algtest->generic_name,
						    enc, seconds);
		else
			ret = test_skcipher_ecb_vec(&skcipher->vecs[i],
						    &perf_stat_arr[i],
						    algtest->generic_name,
						    enc, seconds);

		if (ret)
			goto exit;

		printf("%d ops (%.4lfus/op)\n",
			perf_stat_arr[i].ops,
			perf_stat_arr[i].t_per_op);
	}

	print_performance_stat(perf_stat_arr, algtest->alg_name, enc, skcipher->count);

exit:
	free(perf_stat_arr);
	return ret;
}

static int test_sha_vec(const struct hash_vec *vec,
			struct perf_stat *perf,
			const char *generic_name,
			bool hash_op, uint32_t seconds)
{
	int sock_fd = 0, opfd = 0, ret = 0;
	struct timespec start = { }, end = { };
	uint32_t microseconds = seconds * SEC_TO_MICROSEC;
	char *out;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	memcpy(sa.salg_name, generic_name, strlen(generic_name)+1);

	sock_fd = get_fd_socket(sa);
	if (sock_fd < 0)
		return -1;

	opfd = accept(sock_fd, NULL, 0);
	if (opfd < 0) {
		ret = opfd;
		goto fd_close;
	}

	out = calloc(vec->hashlen, sizeof(char));
	if (!out) {
		ret = -ENOMEM;
		goto opfd_close;
	}

	perf->ops_time = 0;

	while (perf->ops_time < microseconds) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		ret = hash_crypt(opfd, vec->plaintext, vec->psize, out, vec->hashlen);
		if (ret)
			goto exit;

		clock_gettime(CLOCK_MONOTONIC_RAW, &end);

		/* update performance statistics */
		update_performance_stats(perf, vec->psize, &start, &end);
	}

	if (memcmp(out, vec->digest, vec->hashlen)) {
		printf("Hash doesn't match\n");
		hexdump((uint8_t *)out, vec->hashlen);
	}

exit:
	free(out);
opfd_close:
	close(opfd);
fd_close:
	close(sock_fd);
	return ret;
}

static int sha_test(const struct alg_test *algtest, bool hash_op, uint32_t seconds)
{
	const struct hash_suite *hash = &algtest->suite.hash;
	struct perf_stat *perf_stat_arr;
	unsigned int i;
	int ret = 0;

	perf_stat_arr = malloc(hash->count * sizeof(struct perf_stat));
	if (!perf_stat_arr)
		return -ENOMEM;

	for (i = 0; i < hash->count; i++) {
		printf("Doing %s for %ds on %d size: ",
			algtest->alg_name, seconds,
			hash->vecs[i].psize);

		ret = test_sha_vec(&hash->vecs[i],
				   &perf_stat_arr[i],
				   algtest->generic_name,
				   hash_op, seconds);
		if (ret)
			goto exit;

		printf("%d ops (%.4lfus/op)\n",
			perf_stat_arr[i].ops,
			perf_stat_arr[i].t_per_op);
	}

	print_performance_stat(perf_stat_arr, algtest->alg_name, hash_op, hash->count);

exit:
	free(perf_stat_arr);
	return ret;
}

#define VECS(tv)	{ .vecs = tv, .count = ARRAY_SIZE(tv) }
static const struct alg_test alg_test_arr[] = {
	{
		.alg_name = "aes-128-cbc",
		.generic_name = "cbc(aes)",
		.func = skcipher_test,
		.suite = {
			.skcipher = VECS(aes_128_cbc_tv)
		},
	},
	{
		.alg_name = "aes-192-cbc",
		.generic_name = "cbc(aes)",
		.func = skcipher_test,
		.suite = {
			.skcipher = VECS(aes_192_cbc_tv)
		},
	},
	{
		.alg_name = "aes-256-cbc",
		.generic_name = "cbc(aes)",
		.func = skcipher_test,
		.suite = {
			.skcipher = VECS(aes_256_cbc_tv)
		},
	},
	{
		.alg_name = "aes-128-ecb",
		.generic_name = "ecb(aes)",
		.func = skcipher_test,
		.suite = {
			.skcipher = VECS(aes_128_ecb_tv)
		},
	},
	{
		.alg_name = "aes-192-ecb",
		.generic_name = "ecb(aes)",
		.func = skcipher_test,
		.suite = {
			.skcipher = VECS(aes_192_ecb_tv)
		},
	},
	{
		.alg_name = "aes-256-ecb",
		.generic_name = "ecb(aes)",
		.func = skcipher_test,
		.suite = {
			.skcipher = VECS(aes_256_ecb_tv)
		},
	},
	{
		.alg_name = "aes-128-gcm",
		.generic_name = "gcm(aes)",
		.func = aead_test,
		.suite = {
			.aead = VECS(aes_128_gcm_tv)
		},
	},
	{
		.alg_name = "aes-192-gcm",
		.generic_name = "gcm(aes)",
		.func = aead_test,
		.suite = {
			.aead = VECS(aes_192_gcm_tv)
		},
	},
	{
		.alg_name = "aes-256-gcm",
		.generic_name = "gcm(aes)",
		.func = aead_test,
		.suite = {
			.aead = VECS(aes_256_gcm_tv)
		},
	},
	{
		.alg_name = "sha256",
		.generic_name = "sha256",
		.func = sha_test,
		.suite = {
			.hash = VECS(sha256_tv)
		},
	},
	{
		.alg_name = "sha384",
		.generic_name = "sha384",
		.func = sha_test,
		.suite = {
			.hash = VECS(sha384_tv)
		},
	},
};

int run_perf_test(int argc, char *argv[])
{
	int seconds = 0;
	bool enc = 0;
	char *alg_name = NULL, *direction = NULL;

	if (argv[3])
		alg_name = argv[3];
	if (argv[5])
		direction = argv[5];
	if (argv[7])
		seconds = atoi(argv[7]);

	if (argc != MAX_PERF_ARG) {
		print_help(argv[0]);
		return FAILURE;
	}
	if (!strcmp(direction, "enc"))
		enc = 1;
	else if (!strcmp(direction, "dec"))
		enc = 0;
	else if (!strcmp(direction, "hash"))
		enc = 0;
	else {
		print_help(argv[0]);
		printf("Error: invalid direction\n");
		return FAILURE;
	}

	for (int i = 0; i < ARRAY_SIZE(alg_test_arr); i++) {
		if (!strcmp(alg_name, alg_test_arr[i].alg_name))
			return alg_test_arr[i].func(&alg_test_arr[i], enc, seconds);
	}
	printf("Error: invalid alg name\n");
	print_help(argv[0]);
	return FAILURE;
}
