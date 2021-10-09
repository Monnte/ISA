#pragma once

#include "help_functions.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <vector>

using namespace std;

struct fileinfo {
    ofstream *file_ptr;
    vector<char> data;
    int seq;
};

void handle_packet(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

class icmp_server {
  public:
    icmp_server();
    ~icmp_server();
    int init();
    int start();
    int new_file(char *filename, int ID);
    int file_write(int ID, char *data, int datalen, int seq);
    int file_transferd(char *filename, int ID);
    int transfer_error(int ID);
    void handle_data(char *pkt_data,int caplen,int ip_version);

    void exit_server();

  private:
    pcap_t *device;
    int sock;
    char interface[40];
    map<int, struct fileinfo *> connections;
};