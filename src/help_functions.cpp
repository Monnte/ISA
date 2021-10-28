/**
 * @file help_functions.cpp
 * @author Peter Zdravecký (xzdrav00)
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "help_functions.h"

char *encrypt_text(char *in, int in_length, int *out_length) {

    AES_KEY key;
    AES_set_encrypt_key(SECRET_KEY, 256, &key);

    int blocks = (in_length % AES_BLOCK_SIZE ? 1 : 0) + (in_length / AES_BLOCK_SIZE);
    *out_length = blocks * AES_BLOCK_SIZE;

    char *out = (char *)calloc(*out_length, 1);

    if (!out) {
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }

    /* Need to reszie input data to prevent invalid read in for loop */
    char *in_resized = (char *)calloc(*out_length, 1);
    if (!in_resized) {
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }

    memcpy(in_resized, in, in_length);

    for (int i = 0; i < blocks; i++) {
        AES_encrypt((unsigned char *)in_resized + (i * AES_BLOCK_SIZE), (unsigned char *)out + (i * AES_BLOCK_SIZE), &key);
    }

    free(in_resized);

    return (char *)out;
}

char *decrypt_text(char *in, int in_length, int *out_length) {

    AES_KEY key;
    AES_set_decrypt_key(SECRET_KEY, 256, &key);

    int blocks = (in_length % AES_BLOCK_SIZE ? 1 : 0) + (in_length / AES_BLOCK_SIZE);
    *out_length = blocks * AES_BLOCK_SIZE;

    char *out = (char *)calloc(*out_length, 1);

    if (!out) {
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }

    /* Need to reszie input data to prevent invalid read in for loop */
    char *in_resized = (char *)calloc(*out_length, 1);
    if (!in_resized) {
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }

    memcpy(in_resized, in, in_length);

    for (int i = 0; i < blocks; i++) {
        AES_decrypt((unsigned char *)in_resized + (i * AES_BLOCK_SIZE), (unsigned char *)out + (i * AES_BLOCK_SIZE), &key);
    }

    free(in_resized);

    return (char *)out;
}