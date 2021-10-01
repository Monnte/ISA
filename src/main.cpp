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

    char *file_name, *dst_adress;
    int isServer = 0;
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

    if (!file_name) {
        fprintf(stderr, "option -r is required\n");
        return 1;
    }
    if (!dst_adress) {
        fprintf(stderr, "option -s is required\n");
        return 1;
    }

    printf("file_name: %s \nadress: %s \nisServer: %d \n\n", file_name, dst_adress, isServer);

    if (isServer) {
        result = server_transfer();
    } else {
        result = client_transfer(file_name, dst_adress);
    }

    printf("icmp size: %ld\n", sizeof(struct icmp));
    printf("ip size: %ld\n", sizeof(struct ip));
    return result;
}

int server_transfer() { return 0; }

int client_transfer(char *file_name, char *dst_host) {

    char packet[IP_MAXPACKET], data[IP_MAXPACKET];
    struct ip *ip = (struct ip *)packet;
    struct icmp *icmp = (struct icmp *)(packet + sizeof(struct ip));

    char src_name[256];
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in dst;

    int sd;
    const int on = 1;

    // get basic infromation about source and destination
    if (gethostname(src_name, sizeof(src_name)) < 0) {
        fprintf(stderr, "gethostname() error\n");
        return 1;
    }

    if ((src_hp = gethostbyname(src_name)) == NULL) {
        fprintf(stderr, "unknown source: %s\n", src_name);
        return 1;
    }

    ip->ip_src = (*(struct in_addr *)src_hp->h_addr);

    if ((dst_hp = gethostbyname(dst_host)) == NULL) {                       // try get destination by hostname
        if ((ip->ip_dst.s_addr = inet_addr(dst_host)) == (in_addr_t)(-1)) { // try get destination by ip adress
            fprintf(stderr, "unknown destination: %s\n", dst_host);
            return 1;
        }
    } else {
        ip->ip_dst = (*(struct in_addr *)dst_hp->h_addr);
    }

    sprintf(src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(dst_ip, "%s", inet_ntoa(ip->ip_dst));

    printf("Source IP: '%s' -- Destination IP: '%s'\n", src_ip, dst_ip);

    // prepare socket
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        fprintf(stderr, "socket() error\n");
        return 1;
    }
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr, "setsockopt() error\n");
        return 1;
    }

    char send_buf[] = "fajne kubo je frajer ale že fest";
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp));
    ip->ip_id = htons(0);
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;

    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = htons(1000);
    icmp->icmp_seq = htons(0);
    compute_calculated_fields(packet);
    // memcpy(packet + sizeof(struct ip) + sizeof(struct icmp), send_buf, sizeof(send_buf));

    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip->ip_dst.s_addr;

    int dst_addr_len = sizeof(dst);

    if (sendto(sd, packet, sizeof(struct ip) + sizeof(struct icmp), 0, (struct sockaddr *)&dst, dst_addr_len) < 0) {
        perror("sendto() failed ");
    }

    return 0;
}

unsigned char *encrypt_aes(unsigned char *in) {

    AES_KEY key;
    // 32 long by malo byť
    const unsigned char userKey[] = "xzdrav00";
    AES_set_encrypt_key(userKey, 256, &key);

    unsigned char *out = (unsigned char *)malloc(256);
    AES_encrypt(in, out, &key);

    return out;
}

void compute_calculated_fields(char *packet) {

    struct ip *ip = (struct ip *)packet;
    struct icmp *icmp = (struct icmp *)(packet + sizeof(struct ip));
    ip->ip_sum = 0;
    ip->ip_sum = csum(packet, sizeof(struct ip));
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = csum(packet + sizeof(struct ip), 16);
}

__uint16_t csum(char *header, int len) {
    __uint32_t sum = 0;
    for (__uint16_t *ptr = (__uint16_t *)header, *end = (__uint16_t *)(header + len); ptr != end; ptr++)
        sum += *ptr;
    while (sum >> 16)
        sum = ((sum << 16) >> 16) + (sum >> 16);
    return ~(__uint16_t)sum;
}

void handle_exit(int s) {
    if (s == 2) {
        exit(1);
    }
}

void print_help() {
    printf("------------------------\n");
    printf("Secret ICMP file_name Transfer\n");
    printf("\nAuthor: Peter Zdravecký\n");
    printf("------------------------\n");
}
