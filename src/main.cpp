/**
 * @file main.cpp
 * @author Peter Zdravecký (xzdrav00)
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "main.h"

int main(int argc, char **argv) {

    signal(SIGINT, handle_exit);
    /***---------------------------------------------------------------***/
    /** Arugment Parsing
     * @see https://www.gnu.org/software/libc/manual/html_node/Getopt.html
     */

    char *file_name = NULL;
    char *dst_adress = NULL;
    int result = 0;

    /* Parse options and arguments */
    int c;
    while ((c = getopt(argc, argv, "r:s:lh")) != -1) {
        switch (c) {
        case 'r':
            file_name = optarg;
            break;
        case 's':
            dst_adress = optarg;
            break;
        case 'l':
            isServer = 1;
            break;
        case 'h':
            print_help();
            return 0;
        case '?':
            print_help();
            return 1;

        default:
            print_help();
            return 1;
        }
    }

    /* Argument check */
    if (!isServer) {
        if (!file_name) {
            fprintf(stderr, "option -r is required\n");
            print_help();
            return 1;
        }

        if (!dst_adress) {
            fprintf(stderr, "option -s is required\n");
            print_help();
            return 1;
        }
    }

    /* Root check */
    if (getuid() != 0) {
        fprintf(stderr, "%s: this program requires root privileges!\n", argv[0]);
        return 1;
    }

    if (isServer) {
        if (server.init())
            return 1;

        result = server.start();
    } else {
        if (filesystem::is_directory(file_name)) {
            for (const auto &file : filesystem::recursive_directory_iterator(file_name))
                if (!filesystem::is_directory(file.path()))
                    result += client.send_file((char *)(file.path().c_str()), dst_adress);
        } else {
            result = client.send_file(file_name, dst_adress);
        }
    }

    return result;
}

void handle_exit(int s) {
    if (s == 2) {
        if (isServer)
            server.exit_server();

        exit(1);
    }
}

void print_help() {
    printf("------------------------\n");
    printf("Secret ICMP file_name Transfer\n");
    printf("Usage:");
    printf(" ./secret -r [file|folder] -s [ip|hostname] {-l}\n\n");
    printf("    [] - requried options\n");
    printf("    {} - optional options\n\n");

    printf("    -r [file|folder]           - The name of the file to send or folder. Sends all files in folder and its subfolders.\n");
    printf("    -s [ip|hostname]           - Ip address / hostname to which the file should be sent\n");
    printf("    -l                         - Start server and listen for ICMP packet and save files to current folder\n");
    printf("    -h                         - Print help message\n");
    printf("\nNOTE: -l option can be used without -r and -s options.\n");
    printf("NOTE: to set another interface for listening, set it as your system default interface\n");
    printf("NOTE: this program requires root privileges to work correctly\n");
    printf("------------------------\n");
}
