// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 *
 * Author: Gaurav Jain <gaurav.jain@nxp.com>
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
#include "caam-crypt.h"
#include <ctype.h>

/**
 * print_help - print application help
 */
void print_help(char *app)
{
	printf("Application usage: %s [options]\n", app);
	printf("Options:\n");
	printf("      <crypto_op> <algo> [-k <blob_name>]");
	printf(" [-in <input_file>] [-out <output_file>] [-iv <IV value>]\n");
	printf("        <crypto_op> can be enc or dec\n");
	printf("         	    enc for encryption\n");
	printf("         	    dec for decryption (default)\n");
	printf("        <algo> can be AES-256-CBC\n");
	printf("        <blob_name> the absolute path of the file that contains the black blob\n");
	printf("        <input_file> the absolute path of the file that contains input data\n");
	printf("        <output_file> the absolute path of the file that contains output data\n");
	printf("	<IV value> 16 bytes IV value\n");
	return;
}
/**
 * hex_to_int- Utility function for coverting string to hex
 */
int hex_to_int(char c) {
	switch(c) {
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
	case 'A':
		return 0x0A;
	case 'b':
	case 'B':
		return 0x0B;
	case 'c':
	case 'C':
		return 0x0C;
	case 'd':
	case 'D':
		return 0x0D;
	case 'e':
	case 'E':
		return 0x0E;
	case 'f':
	case 'F':
		return 0x0F;
    }
    return FAILURE;
}

static int convert_to_hex(const char* input, char* output, unsigned int size)
{
        unsigned int i = 0, n = 0;
        unsigned char high_nibble, low_nibble;

        i = size * 2;
        n = strlen(input);
        if (n > i) {
                printf("Hex string is too long, ignoring excess\n");
                n = i; /* Ignoring extra part */
        } else if (n < i) {
                printf("Hex string is too short, padding with zero bytes to length\n");
        }

        memset(output, 0, size);
        for (i = 0; i < n; i += 2) {
                high_nibble = (unsigned char)*input++; /*first character */
                low_nibble = (unsigned char)*input++; /*second character */
                /* Check if both characters are valid hexadecimal digits */
                if (!isxdigit(high_nibble) || !isxdigit(low_nibble)) {
                        printf("Non-hex digit\n");
                        return FAILURE;
                }
        /* Convert nibble to its integer value */
        high_nibble = (unsigned char)hex_to_int(high_nibble);
        low_nibble = (unsigned char)hex_to_int(low_nibble);
        output[i / 2] = (high_nibble << 4) | low_nibble;
    }
    return SUCCESS;
}

/**
 * get_fd_socket - get file descriptor for a new socket
 *
 * @sa              : The information about the algorithm we want to use for
 *                    encryption or decryption
 *
 * Return           : file descriptor on success, -1 otherwise
 */
int get_fd_socket(struct sockaddr_alg sa)
{
	int sock_fd = 0, err = 0;

	/*
	 * AF_ALG is the address family we use to interact with Kernel
	 * Crypto API. SOCK_SEQPACKET is used because we always know the
	 * maximum size of our data (no fragmentation) and we care about
	 * getting things in order in case there are consecutive calls
	 */
	sock_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sock_fd < 0) {
		printf("Failed to allocate socket\n");
		return FAILURE;
	}

	err = bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa));
	if (err) {
		printf("Failed to bind socket, alg may not be supported\n");
		close(sock_fd);
		return -EAFNOSUPPORT;
	}

	return sock_fd;
}

/**
 * caam_import_black_key - Import black key from black blob using caam-keygen app
 *
 * @blob_name       : absolute path of the file that conatins the black blob
 *
 * Return           : '0' on success, -1 otherwise
 */
int caam_import_black_key(char *blob_name)
{
	pid_t cpid, w;
	int status;
	char *argv[] = {CAAM_KEYGEN_APP, CAAM_KEYGEN_IMPORT, NULL, KEY_NAME, NULL};

	argv[2] = blob_name;
	/*
	* Command to be execute, to create a black key is:
	* /usr/bin/caam-keygen import <blob_name> <key_name>
	* where:
	* <blob_name> the absolute path of the file that contains the blob
	* <key_name> the name of the file that will contain the black key.
	*/
	cpid = fork();
	if (cpid == FAILURE) {
		printf("Failed to fork process.\n");
		return FAILURE;
	}

	if (cpid == 0) {
		/* Execute command to import black key at KEY_LOCATION */
		if (execvp(argv[0], argv) < 0) {
			printf("Failed to execute command.\n");
			return FAILURE;
		}
	} else {
		/* Wait for process to finish execution */
		do {
			w = waitpid(cpid, &status, WUNTRACED | WCONTINUED);
			if (w == FAILURE) {
				printf("Fail to wait for process to finish execution.\n");
				return FAILURE;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	}
	return SUCCESS;
}

/**
 * skcipher_crypt - Encryption or decryption of an input
 *
 * @tfmfd           : The file descriptor for socket
 * @vec             : structure that contains key, iv, ptext/ctext.
 * @encrypt         : Used to determine if it's an encryption or decryption
 *                    operation
 * @output          : The output from encryption/decryption
 *
 * Return           : '0' on success, -1 otherwise
 */
int skcipher_crypt(int tfmfd, const struct aes_cipher *vec, bool encrypt, char *output)
{
	int opfd, err;
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *af_alg_iv;
	struct iovec iov;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};

	/* Set socket options for key */
	err = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, vec->key, vec->klen);
	if (err) {
		printf("Failed to set socket key, err = %d\n", err);
		return err;
	}

	/*
	 * Once it's "configured", we tell the kernel to get ready for
	 * receiving some requests
	 */
	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		printf("Failed to open connection for the socket\n");
		return -EBADF;
	}

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);

	af_alg_iv = (void *)CMSG_DATA(cmsg);
	af_alg_iv->ivlen = 16;
	memcpy(af_alg_iv->iv, vec->iv, af_alg_iv->ivlen);

	iov.iov_base = encrypt ? vec->ptext : vec->ctext;
	iov.iov_len = vec->len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/*
	 * Start sending data to the opfd and read back
	 * from it to get our encrypted/decrypted data
	 */
	if (sendmsg(opfd, &msg, 0) < 0) {
		printf("Failed to send message.\n");
		return FAILURE;
	}
	if (read(opfd, output, vec->len) < 0) {
		printf("Failed to read.\n");
		return FAILURE;
	}
	close(opfd);
	return SUCCESS;
}

/**
 * store_data - store the data in a file
 *
 * @file            : absolute path of the file that will contain output data
 * @output_text     : pointer to output data buffer
 * @len             : length of output data buffer
 *
 * Return           : '0' on success, -1 otherwise
 */
int store_data(char *file, char *output_text, unsigned int len,
			 bool encrypt)
{	int ret = SUCCESS;
	FILE *fp;
	fp = fopen(file, "wb");
	if (!fp) {
		printf("Failed to create %s.\n", file);
		return FAILURE;
	}
	if (encrypt) {
		if (fwrite(output_text, sizeof(char), len, fp) != len) {
			printf("Failed to write in %s.\n", file);
			ret = FAILURE;
			goto file_close;
		}
	} else {
		/* Note:- Caam-crypt application supports PKCS#7 padding
		 * scheme only.
		 * Last byte stores no. of padded bytes in PKCS#7 padding
		 * scheme
		 */
		int padding_bytes_len = output_text[len - 1];
		int final_len = len - padding_bytes_len;

		if (fwrite(output_text, sizeof(char), final_len, fp) != final_len) {
			printf("Failed to write in %s.\n", file);
			ret = FAILURE;
			goto file_close;
		}
	}

file_close:
	fclose(fp);

	return ret;
}

/**
 * read_file - read file in a buffer
 *
 * @file            : the absolute path of the file
 * @buf             : double ptr to buffer that contain the data read from file
 * @len             : length of file to be read
 *
 * Return           : '0' on success, -1 otherwise
 */
int read_file(char *file, char **buf, unsigned int *len)
{
	FILE *fp;
	struct stat file_st;

	/* Get file size */
	if (stat(file, &file_st)) {
		printf("Failed to get file status.\n");
		return FAILURE;
	}
	*len = file_st.st_size;

	fp = fopen(file, "rb");
	if (!fp) {
		printf("Failed to open file.\n");
		return FAILURE;
	}

	*buf = calloc(*len, sizeof(char));
	if (*buf == NULL) {
		printf("Failed to allocate memory.\n");
		fclose(fp);
		return FAILURE;
	}

	if (fread(*buf, sizeof(char), *len, fp) != *len) {
		printf("Failed to read data from file.\n");
		free(*buf);
		fclose(fp);
		return FAILURE;
	}

	fclose(fp);
	return SUCCESS;
}

int main(int argc, char *argv[])
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",	/* selects the symmetric cipher */
		.salg_name = "tk(cbc(aes))"	/* this is the cipher name */
	};
	int sock_fd, ret = 0;
	bool encrypt_op = false;
	char *key_file = NULL;
	char *blob = NULL;
	char *algo = NULL;
	char *file = NULL;
	char *output_text = NULL;
	char *plain_text = NULL;
	struct aes_cipher vec = {};

	if (argc != MAX_ARG) {
		print_help(argv[0]);
		return FAILURE;
	}
	if (!strcmp(argv[1], "enc")) {
		encrypt_op = true;
	} else if (strcmp(argv[1], "enc") && strcmp(argv[1], "dec")) {
		printf("Invalid crypto operation.\n");
		print_help(argv[0]);
		return FAILURE;
	}
	algo = argv[2];
	if (strcmp(algo, "AES-256-CBC")) {
		printf("encryption algo not supported\n");
		print_help(argv[0]);
		return FAILURE;
	}

	/* Import black key(ECB or CCM) from black blob */
	blob = argv[4];
	ret = caam_import_black_key(blob);
	if (ret) {
		printf("Failed to import black key from black blob.\n");
		return ret;
	}

	/* Read black key from key file(KEY_NAME) */
	key_file = malloc(strlen(KEY_NAME) + strlen(KEY_LOCATION) + 1);
	if (!key_file) {
		printf("Failed to allocate memory for key file.\n");
		return FAILURE;
	}
	strcpy(key_file, KEY_LOCATION);
	strcat(key_file, KEY_NAME);

	ret = read_file(key_file, &vec.key, &vec.klen);
	if (remove(key_file)) {
		printf("Failed to remove file %s.\n", key_file);
	}
	free(key_file);
	if (ret) {
		printf("Failed to read key file or file doesn't exist.\n");
		return ret;
	}

	/*
	 * Read data from input file
	 * Input next to -in option is input file
	 */
	if (!strcmp(argv[5], "-in")) {
		file = argv[6];
		if (encrypt_op) {
			/*
			 * In case of encryption, input data is in
			 * plain format.
			 */
			ret = read_file(file, &plain_text, &vec.len);
			if (ret) {
				printf("Failed to read plain text file or file doesn't exist.\n");
				goto free_key;
			}
			/*
			 * Padding plain data with PKCS#7 based padding style
			 * for making it multiple of block size.
			 */
			int bytes_to_pad = BLOCK_SIZE - (vec.len) % BLOCK_SIZE;
			vec.ptext = realloc(plain_text, (sizeof(char)) * (vec.len +
					    bytes_to_pad));
			if (!vec.ptext) {
				printf("Failed to allocate memory.\n");
				ret = FAILURE;
				goto free_key;
			}

			for (int i = vec.len; i < vec.len + bytes_to_pad ; i++)
				vec.ptext[i] = bytes_to_pad;
			vec.len += bytes_to_pad;
		} else {
			/*
			 * In case of decryption, data is cipher, text which we need
			 * to decrypt.
			 */
			ret = read_file(file, &vec.ctext, &vec.len);
			if (ret) {
				printf("Failed to read enc file or file doesn't exist.\n");
				goto free_key;
			}
		}
	} else {
		print_help(argv[0]);
		ret = FAILURE;
		goto free_key;
	}

	/* Converting user provided IV to appropriate format. */
	vec.iv = (char *)malloc(IV_LEN);
	if (!vec.iv) {
		printf("Failed to allocate memory.\n");
		ret = FAILURE;
		goto free_text;
	}

	ret = convert_to_hex(argv[10], vec.iv, IV_LEN);
	if (ret) {
		print_help(argv[0]);
		goto free_iv;
	}
	output_text = calloc(vec.len, sizeof(char));
	if (!output_text) {
		printf("Failed to allocate memory for output text.\n");
		ret = FAILURE;
		goto free_iv;
	}

	/* tk(cbc(aes)) algorithm */
	sock_fd = get_fd_socket(sa);
	if (sock_fd < 0) {
		ret = FAILURE;
		goto free_output;
	}

	/* Calling skcipher for encrypt/decrypt operation. */
	ret = skcipher_crypt(sock_fd, &vec, encrypt_op, output_text);
	if (ret) {
		printf("Failed to decrypt.\n");
		goto fd_close;
	}

	/* Write data in output file */
	if (!strcmp(argv[7], "-out")) {
		file = argv[8];
		ret = store_data(file, output_text, vec.len, encrypt_op);
	} else {
		print_help(argv[0]);
	}
fd_close:
	close(sock_fd);
free_output:
	free(output_text);
free_iv:
	free(vec.iv);
free_text:
	if (encrypt_op)
		free(vec.ptext);
	else
		free(vec.ctext);
free_key:
	free(vec.key);
	return ret;
}
