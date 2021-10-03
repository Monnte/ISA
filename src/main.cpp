/**
 * @file_name main.cpp
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @brief Network packet capturing with filter options
 * @version 0.1
 * @date 2021-09-28
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "main.h"

int main(int argc, char **argv) {

    if (getuid() != 0) {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        return 1;
    }

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
    while ((c = getopt(argc, argv, "r:s:l::")) != -1) {
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
        case '?':
            return 1;
        default:
            return 1;
        }
    }

    if (!isServer) {

        if (!file_name) {
            fprintf(stderr, "option -r is required\n");
            return 1;
        }

        if (!dst_adress) {
            fprintf(stderr, "option -s is required\n");
            return 1;
        }
    }

    if (isServer) {
        if (server.init())
            return 1;

        result = server.start();
    } else {

        result = client.send_file(file_name, dst_adress);
    }

    return result;
}

int server_transfer() { return 0; }

void handle_exit(int s) {
    if (s == 2) {
        if (isServer) {
            server.exit_server();
        }
        exit(1);
    }
}

void print_help() {
    printf("------------------------\n");
    printf("Secret ICMP file_name Transfer\n");
    printf("\nAuthor: Peter Zdravecký\n");
    printf("------------------------\n");
}
