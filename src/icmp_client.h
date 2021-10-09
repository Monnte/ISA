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
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;
unsigned short csum(char *b, int len);



class icmp_client {
  public:
    icmp_client();
    ~icmp_client();
    int send_file(char *file_name, char *dst_host);
    int dnslookup();
    char *create_packet(struct secret_proto *proto, char *data, int datalen);
    int prepare_file();
    char *get_file_data(int len, int *datalen);

    int send_pkt(char *data, int datalen, int pck_type);
    int get_dest_info();
    int prepare_socket();

   

  private:
    char *file_name;
    char *dst_host;
    ifstream file;
    int sock;
    int client_id;
    struct addrinfo *dest;
};