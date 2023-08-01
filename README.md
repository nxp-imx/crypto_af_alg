# 1. Overview
This document provides a step-by-step procedure on how to encrypt/decrypt a file without disclosing the key in the kernel using caam-crypt application.

# 2. Black keys
Represent keys stored in memory in encrypted form and decrypted on-the-fly when used.

# 3. Blobs
CAAM provides a method to protect data, across system power cycles, in a cryptographic data structure called blob. The data to be protected is encrypted so that it can be safely placed into non-volatile storage. blobs can only be decapsulated by the SoC that created it.
Encapsulation of black key is called black blob. The decapsulation will result in a new black key readable only by the CAAM HW.


# 4. Prerequisites

## 4.1 Importing black key using caam-keygen application
caam-keygen application is needed to import black key from black blob. Make sure that caam-keygen app is already present at /usr/bin.

## 4.2 PKCS#7 Padding Scheme
caam-crypt application assumes that plaintext must be padded as per pkcs#7 padding scheme and then encrypted.

# 5. Build the kernel

## 5.1 Kernel configuration
- CONFIG_CRYPTO_USER_API
- CONFIG_CRYPTO_USER_API_HASH
- CONFIG_CRYPTO_USER_API_SKCIPHER
- CONFIG_CRYPTO_USER_API_RNG
- CONFIG_CRYPTO_USER_API_AEAD

Get a bootable image that includes the black key support and AF_ALG socket interface for Linux kernel. Or build the kernel from here: https://source.codeaurora.org/external/imx/linux-imx/. For more details refer to i.MX Linux User's Guide from https://www.nxp.com/


## 5.2 Build a toolchain
Build a toolchain in order to cross compile the sources of the caam-crypt application. For details refer to i.MX Yocto Project User's Guide from https://www.nxp.com/

```
$ wget https://developer.arm.com/-/media/Files/downloads/gnu-a/8.2-2019.01/gcc-arm-8.2-2019.01-x86_64-aarch64-elf.tar.xz
$ tar xf gcc-arm-8.2-2019.01-x86_64-aarch64-elf.tar.xz
```

## 5.3 Cross compile the user space sources
Setup the environment for cross compilation using the toolchain previously prepared.

- From the toolchain folder set up the environment:

```
  $ export CROSS_COMPILE=<path to toolchain>/bin/aarch64-linux-gnu-
  $ export CC=${CROSS_COMPILE}gcc
  $ export LD=${CROSS_COMPILE}ld
```
- Build the caam-crypt user space application, go to source folder and run:

```
  $ make clean
  $ make
```

# 6. Usage
After the device successfully boots with the previously generated image,
caam-crypt can be used to encrypt/decrypt a plain/encrypted data stored in a file
respectively.

```
  $ ./caam-crypt
Application usage: caam-crypt [options]
Options:
For running performance test:-
	perf [-algo <algo_name>] [-dir <direction>] [-seconds <time in sec>]
	<algo_name> can be below:-
			aes-128-ecb, aes-192-ecb, aes-256-ecb
			aes-128-cbc, aes-192-cbc, aes-256-cbc
			aes-128-gcm, aes-192-gcm, aes-256-gcm
			sha256, sha384
	<direction> can be enc, dec or hash
	<time in sec> seconds > 0
For encryption/decryption operations:-
	<crypto_op> <algo> [-k <blob_name>] [-in <input_file>] [-out <output_file>] [-iv <IV value>]
	<crypto_op> can be enc or dec
		    enc for encryption.
		    dec for decryption.
	<algo> can be AES-256-CBC
	<blob_name> the absolute path of the file that contains the black blob
	<input_file> the absolute path of the file that contains input data
		     In case of encryption, input file will contain plain data.
		     In case of decryption, input file will contain encrypted data.
	<output_file> the absolute path of the file that contains output data
	<IV value> 16 bytes IV value
```

# 7. Use case example

```
For Performance benchmarking:-

  $ caam-crypt perf -algo <algo_name> -dir <direction> -seconds <no.of sec>

For encryption:-

  $ caam-crypt enc AES-256-CBC -k myblob -in <plain_text_file> -out <encrypted_file> -iv <16-byte IV value>

For decryption:-

  $ caam-crypt dec AES-256-CBC -k myblob -in <encrypted_file> -out <decrypted_file> -iv <16-byte IV value>
```

where:

- algo_name - Crypto operation name
- direction - It can be enc, dec or hash.
- no. of sec - Time for which performance need to be measured.
- myblob - generated black key blob. caam-keygen application will import a black key from black blob. this black key will be used by CAAM for encryption/decryption.
- AES-256-CBC - currently the only supported symmetric algorithm used for encryption/decryption operation.
		NOTE:- User has to make sure that algorithm used for encryption/decryption should be same.
- encrypted_file - Encrypted data stored in a file.
- plain_text_file - Plain text stored in a file (Padding is added for making
		    data as multiples of block size).
- decrypted_file - Decrypted data stored in a file.
- iv - 16 bytes IV value
```
AES Encrypted file format
	nn Octets - Encrypted message
```
