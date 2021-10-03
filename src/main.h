/**
 * @file main.h
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "icmp_client.h"
#include "icmp_server.h"
#include <signal.h>
#include <stdio.h>

icmp_server server;
icmp_client client;
int isServer = 0;

using namespace std;

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
