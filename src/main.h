/**
 * @file main.h
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/aes.h>

using namespace std;
#define HEADER_SIZE 20

/**
 * @brief Handling keyboard interrupt signal. Correctly shuts down sniffer
 *
 * @param s signal code
 */
void handle_exit(int s);

/**
 * @brief Prints program help and usage
 */
void print_help();

int server_transfer();
int client_transfer(char *file_name, char *dst_host);
void compute_calculated_fields(char *packet);
unsigned char *encrypt_aes(unsigned char *in);
__uint16_t csum(char *header, int len);
