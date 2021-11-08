/**
 * @file icmp_server.h
 * @author Peter Zdravecký (xzdrav00)
 * @brief
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */
#pragma once

#include "cipher.h"
#include "secret_proto.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <map>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace std;

/**
 * @brief function for pcap_loop callback for handling packets
 *
 * @param user user data passed from pcap_loop fucntion
 * @param pkt_header packet header information (time / packet length)
 * @param pkt_data packet data
 */
void handle_packet(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

class icmp_server {
  public:
    /**
     * @brief Construct a new icmp server object
     *
     */
    icmp_server();

    /**
     * @brief Destroy the icmp server object
     *
     */
    ~icmp_server();

    /**
     * @brief Configure server and compile filter for packet capturing.
     *
     * @return sucess = 0 / fail = 1
     */
    int init();

    /**
     * @brief Starts captruing packets loop.
     *
     * @return sucess = 0 / fail = 1
     */
    int start();

    /**
     * @brief Parse packet and recive data from it
     *
     * @param pkt_data packet data
     * @param caplen captrued length of packet
     * @param ip_version verison of ip protocol
     */
    void handle_data(char *pkt_data, int caplen, int ip_version);

    /**
     * @brief Handle new connection and create new file descriptor for writing.
     *
     * @param filename Filneame for new file
     * @param ID ID of transfer
     * @return sucess = 0 / fail = 1
     */
    int new_file(char *filename, int ID);

    /**
     * @brief Write data to file.
     *
     * @param ID ID of trasnfer
     * @param data data to write
     * @param datalen data length
     * @param seq sequence number of packet
     * @return sucess = 0 / fail = 1
     */
    int file_write(int ID, char *data, int datalen, int seq);

    /**
     * @brief Handle end of connection. Clears allocated data and closing file. Prints message of sucesfull transfer
     *
     * @param filename FIlename to be printed
     * @param ID ID of transfer
     * @return sucess = 0 / fail = 1
     */
    int file_transferd(char *filename, int ID);

    /**
     * @brief Handle transfer error. Clears allocated data and closing file. Prints error message.
     *
     * @param ID ID of transfer
     * @return sucess = 0 / fail = 1
     */
    int transfer_error(int ID);

    /**
     * @brief Correctly shutdown server
     *
     */
    void exit_server();

    /**
     * @brief Structure holding basic infromationd of connection
     *
     */
    struct fileinfo {
        ofstream *file_ptr; /* File descriptor */
        vector<char> data;  /* Data accumulator */
        int seq;            /* Seqence number of packet */
    };

  private:
    pcap_t *device;                          /* Device on which packets are sniffed */
    map<int, struct fileinfo *> connections; /* Map for active connections */
};