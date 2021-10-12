/**
 * @file main.h
 * @author Peter Zdravecký (xzdrav00)
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "icmp_client.h"
#include "icmp_server.h"
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <string>

using namespace std;

icmp_server server;
icmp_client client;
int isServer = 0;

/**
 * @brief Handling keyboard interrupt signal. Correctly shuts down program
 *
 * @param s signal code
 */
void handle_exit(int s);

/**
 * @brief Prints program help and usage
 */
void print_help();