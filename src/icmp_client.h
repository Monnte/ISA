#pragma once

#include "help_functions.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <libgen.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

class icmp_client {
  public:
    icmp_client();
    ~icmp_client();
    int send_file(char *file_name, char *dst_host);
    int set_src_dst_ip();
    char *create_packet(struct secret_proto *proto, char *data, int datalen);
    int prepare_file();
    char *get_file_data(int len, int *datalen);

    int send_head_pkt(struct sockaddr_in *dst);
    int send_pkt(struct sockaddr_in *dst, char *data, int datalen, int pck_type);
    int send_end_pkt(struct sockaddr_in *dst);

    int prepare_socket();
    unsigned short csum(char *b, int len);

  private:
    char *file_name;
    char *dst_host;
    in_addr src_ip, dst_ip;
    ifstream file;
    int sock;
    int client_id;
};