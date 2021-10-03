#pragma once

#include <cstdlib>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECRET_KEY (unsigned char *)"xzdrav00"

enum pkt_type { HEAD, DATA, END };

struct secret_proto {
    char proto_name[4] = "MNT";
    int type;
    int datalen;
    int seq;
    int client_id;
};

char *encrypt_text(char *in, int in_length, int *out_length);
char *decrypt_text(char *in, int in_length, int *out_length);