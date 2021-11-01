/**
 * @file icmp_client.cpp
 * @author Peter Zdravecký (xzdrav00)
 * @version 0.1
 * @date 2021-10-10
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "icmp_client.h"

icmp_client::icmp_client() {
    /* Set client id */
    srand(time(NULL));
    this->client_id = rand();
}

icmp_client::~icmp_client() {}

int icmp_client::get_dest_info() {
    struct addrinfo hints, *info;
    int res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    if ((res = getaddrinfo(this->dst_host, NULL, &hints, &(this->dest))) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        return 1;
    }

    /** @see https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
     * There are several reasons why the linked list may have more than
     *    one addrinfo structure, including: the network host is
     *    multihomed, accessible over multiple protocols (e.g., both
     *    AF_INET and AF_INET6); or the same service is available from
     *    multiple socket types (one SOCK_STREAM address and another
     *    SOCK_DGRAM address, for example).
     */
    for (info = this->dest; info != NULL; info = info->ai_next) {
        if ((this->sock = socket(info->ai_family, info->ai_socktype, info->ai_family == AF_INET ? (int)IPPROTO_ICMP : (int)IPPROTO_ICMPV6)) == -1)
            continue;

        break;
    }

    if (this->sock == -1) {
        perror("socket failed");
        return 1;
    }

    /* Set file descriptor for pooling */
    fds->fd = this->sock;
    fds->events = POLLOUT; /* Event writing is now possible */

    return 0;
}

int icmp_client::send_file(char *file_name, char *dst_host) {
    printf("File Name: %s | Adress: %s\n-----------------------------\n", file_name, dst_host);
    this->file_name = file_name;
    this->dst_host = dst_host;
    this->sequence = 0;

    if (this->get_dest_info())
        return 1;

    if (this->prepare_file())
        return 1;

    /* Send packet announcing the start of the transfer */
    if (send_pkt(basename(this->file_name), strlen(basename(this->file_name)), pkt_type::HEAD))
        return 1;

    /* Send file data */
    printf("Sending file ... | Transfer ID: %d\n", this->client_id);

    while (!file.eof()) {
        int datalen = 0;

        char *data = get_file_data(MAX_DATA_LENGTH, &datalen);
        if (!data)
            return 1;

        if (datalen == 0) {
            fprintf(stderr, "Error while reading file\n");
            return 1;
        }

        if (send_pkt(data, datalen, pkt_type::DATA))
            return 1;

        free(data);
    }
    this->file.close();

    /* Send packet announcing the end of the transfer */
    if (send_pkt(basename(this->file_name), strlen(basename(this->file_name)), pkt_type::END))
        return 1;

    /* Close and free allocated resources */
    close(this->sock);
    freeaddrinfo(this->dest);

    printf("\nSuccesfully sended file: %s\n\n", basename(this->file_name));
    return 0;
}

int icmp_client::send_pkt(char *data, int datalen, int pck_type) {

    struct secret_proto protocol;
    protocol.datalen = datalen;
    protocol.type = pck_type;
    protocol.client_id = this->client_id;
    protocol.seq = this->sequence++;

    int encrypted_data_len = 0;
    char *encrypted_data = NULL;

    if (datalen > 0) {
        encrypted_data = encrypt_text(data, datalen, &encrypted_data_len);
        if (!encrypted_data)
            return 1;
    }

    char *packet = create_packet(&protocol, encrypted_data, encrypted_data_len);
    if (!packet) {
        return 1;
    }

    int packet_size = sizeof(struct icmphdr) + sizeof(struct secret_proto) + encrypted_data_len;

    /* Wait for socket to be ready to send */
    poll(this->fds, 1, POLL_TIEMOUT);
    /* Send packet */
    if ((sendto(this->sock, packet, packet_size, 0, (struct sockaddr *)(this->dest->ai_addr), this->dest->ai_addrlen)) < 0) {
        perror("sendto() failed");
        return 1;
    }

    /* Free allocated resources */
    if (encrypted_data)
        free(encrypted_data);

    if (packet)
        free(packet);

    return 0;
}

char *icmp_client::create_packet(struct secret_proto *proto, char *data, int datalen) {
    int icmp_len = sizeof(struct icmphdr);
    int proto_len = sizeof(struct secret_proto);

    char *packet = (char *)calloc(icmp_len + proto_len + datalen, 1);
    if (!packet) {
        fprintf(stderr, "malloc failed\n");
        return packet;
    }

    struct icmphdr *icmp = (struct icmphdr *)(packet);
    icmp->type = this->dest->ai_family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->code = 0;

    /* Copy secret_proto to end of icmp header */
    memcpy(packet + icmp_len, proto, proto_len);
    /* Copy data to end of secret_proto*/
    memcpy(packet + (icmp_len + proto_len), data, datalen);

    /* Calculate checksum */
    icmp->checksum = 0;
    icmp->checksum = csum(packet, icmp_len + proto_len + datalen);

    return packet;
}

int icmp_client::prepare_file() {
    /* Check if file exists */
    if (!access(this->file_name, F_OK) == 0) {
        fprintf(stderr, "file doesn't exist\n");
        return 1;
    }

    /* Try to open file */
    this->file = ifstream(this->file_name, ios::binary);

    if (!this->file.is_open()) {
        fprintf(stderr, "cannot open file\n");
        return 1;
    }

    /* Get file lenght */
    this->file.seekg(0, this->file.end);
    unsigned long long length = this->file.tellg();
    this->file.seekg(0, this->file.beg);

    if (length == 0) {
        fprintf(stderr, "File is empty, there is nothig to be transferd\n");
        return 1;
    }

    return 0;
}

char *icmp_client::get_file_data(int len, int *datalen) {
    char *data = (char *)calloc(len, 1);
    if (!data) {
        fprintf(stderr, "malloc failed\n");
        return data;
    }

    this->file.read(data, len);

    /* Gives acttual readed length */
    if (this->file)
        *datalen = len;
    else
        *datalen = this->file.gcount();

    return data;
}

/** @see ISA/examples/raw/icmp4.c */
unsigned short icmp_client::csum(char *data, int len) {
    unsigned short *addr = (unsigned short *)data;
    int count = len;
    unsigned int sum = 0;
    unsigned short answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}