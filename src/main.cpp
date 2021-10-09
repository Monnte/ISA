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

    if (getuid() != 0) {
        fprintf(stderr, "%s: this program requires root privileges!\n", argv[0]);
        return 1;
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
        if (isServer)
            server.exit_server();

        exit(1);
    }
}

void print_help() {
    printf("------------------------\n");
    printf("Secret ICMP file_name Transfer\n");
    printf("Usage:");
    printf(" ./secret -r [file] -s [ip|hostname] {-l}\n\n");
    printf("    [] - requried options\n");
    printf("    {} - optional options\n\n");

    printf("    -r [file]                  - The name of the file to send\n");
    printf("    -s [ip|hostname]           - Ip address / hostname to which the file should be sent\n");
    printf("    -l                         - Start server and listen for ICMP packet and save files to current folder\n");
    printf("    -h                         - Print help message\n");
    printf("\nNOTE: -l option can be used without -r and -s options.\n");
    printf("\nNOTE: this program requires root privileges to work correctly\n");
    printf("\nAuthor: Peter Zdravecký\n");
    printf("------------------------\n");
}
