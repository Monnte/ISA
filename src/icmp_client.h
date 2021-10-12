/**
 * @file icmp_client.h
 * @author Peter Zdravecký (xzdrav00)
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */
#pragma once

#include "help_functions.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <fstream>
#include <iostream>
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

class icmp_client {
  public:
    /**
     * @brief Construct a new icmp client object
     *
     */
    icmp_client();

    /**
     * @brief Destroy the icmp client object
     *
     */
    ~icmp_client();

    /**
     * @brief Resolve infromation of destination and create socket for communication
     *
     * @return sucess = 0 / fail = 1
     */
    int get_dest_info();

    /**
     * @brief Main function for this module. Sends file to destination
     *
     * @param file_name Name of file to be sended
     * @param dst_host Ip adress or hostname of destination
     * @return sucess = 0 / fail = 1
     */
    int send_file(char *file_name, char *dst_host);

    /**
     * @brief Send packet
     *
     * @param data transporeted data
     * @param datalen transported data length
     * @param pck_type type of packet to be sended
     * @return sucess = 0 / fail = 1
     */
    int send_pkt(char *data, int datalen, int pck_type);

    /**
     * @brief Create a packet and fill with infromation
     *
     * @param proto secret protocol data
     * @param data transporeted data
     * @param datalen transported data length
     * @return pointer to packet data
     */
    char *create_packet(struct secret_proto *proto, char *data, int datalen);

    /**
     * @brief Read data from file.
     *
     * @param len length to read
     * @param datalen actuall readed length
     * @return pointer to data
     */
    char *get_file_data(int len, int *datalen);

    /**
     * @brief Try to open file
     *
     * @return sucess = 0 / fail = 1
     */
    int prepare_file();

    /**
     * @brief Checksum function for icmp heder
     * @see ISA/examples/raw/icmp4.c
     *
     * @param data pointer to data
     * @param len data length
     * @return checksum
     */
    unsigned short csum(char *data, int len);

  private:
    char *file_name;
    char *dst_host; /* ip adress / hostname of destination */
    ifstream file;
    int sock;
    int client_id;
    struct addrinfo *dest;
    int sequence; /* sequence number of sended packet - reset when sending new file */
};