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
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

struct fileinfo {
    ofstream *file_ptr;
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
    int file_corrupted(int ID);
    void exit_server();

  private:
    pcap_t *device;
    int sock;
    char interface[40];
    map<int, struct fileinfo *> connections;
};