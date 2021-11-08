/**
 * @file cipher.h
 * @author Peter Zdravecký
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */
#pragma once

#include <cstdlib>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECRET_KEY (unsigned char *)"xzdrav00"

/**
 * @brief Encrpyt data with AES encryption
 * @see https://man.openbsd.org/AES_encrypt.3
 *
 * @param in data to be encrypted
 * @param in_length length of in data
 * @param out_length returns length of encrypted data
 * @return encrypted data
 */
char *encrypt_text(char *in, int in_length, int *out_length);

/**
 * @brief Decrypt data with AES decryption
 * @see https://man.openbsd.org/AES_encrypt.3
 *
 * @param in data to be encrypted
 * @param in_length length of in data
 * @param out_length returns length of decrpyted data
 * @return decrpyted data
 */
char *decrypt_text(char *in, int in_length, int *out_length);