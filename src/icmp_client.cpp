#include "icmp_client.h"
icmp_client::icmp_client() {
    srand(time(NULL));
    this->client_id = rand();
}

icmp_client::~icmp_client() {}

int icmp_client::get_dest_info() {
    struct addrinfo hints;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    if ((rv = getaddrinfo(this->dst_host, NULL, &hints, &(this->dest))) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    return 0;
}

int icmp_client::send_file(char *file_name, char *dst_host) {
    printf("File Name: %s | Adress: %s\n-----------------------------\n", file_name, dst_host);
    this->file_name = file_name;
    this->dst_host = dst_host;

    if (this->prepare_file())
        return 1;

    if (this->get_dest_info())
        return 1;

    if (this->prepare_socket())
        return 1;

    // send start packet
    if (send_pkt(basename(this->file_name), strlen(basename(this->file_name)), pkt_type::HEAD))
        return 1;

    printf("Sending file ... | Transfer ID: %d\n",this->client_id);
    // send data
    int max_data_len = ETHERMTU - (this->dest->ai_family == AF_INET ? sizeof(struct ip) : sizeof(struct ip6_hdr)) - sizeof(struct icmp) - sizeof(struct secret_proto) -
                       AES_BLOCK_SIZE; // HEADERS + PROTOCOLS - reservere block for encrypted data

    while (!file.eof()) {
        int datalen = 0;
        char *data = get_file_data(max_data_len, &datalen);

        if (!data)
            return 1;

        if (datalen == 0) {
            fprintf(stderr, "error while reading file\n");
            return 1;
        }

        if (send_pkt(data, datalen, pkt_type::DATA))
            return 1;


        free(data);
    }
    this->file.close();

    // send end packet
    if (send_pkt(basename(this->file_name), strlen(basename(this->file_name)), pkt_type::END))
        return 1;

    close(this->sock);
    freeaddrinfo(this->dest);


    printf("\nSuccesfully sended file: %s\n", this->file_name);

    return 0;
}

int icmp_client::send_pkt(char *data, int datalen, int pck_type) {
    static int sequence = 0;

    struct secret_proto protocol;
    protocol.datalen = datalen;
    protocol.type = pck_type;
    protocol.client_id = this->client_id;
    protocol.seq = sequence++;

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

    int packet_size = sizeof(struct icmp) + sizeof(struct secret_proto) + encrypted_data_len;

    int transfered_len = 0;
    if ((transfered_len = sendto(this->sock, packet, packet_size, 0, (struct sockaddr *)(this->dest->ai_addr),this->dest->ai_addrlen)) < 0) {
        perror("sendto() failed");
        return 1;
    }

    if (encrypted_data)
        free(encrypted_data);

    if (packet)
        free(packet);

    return 0;
}

char *icmp_client::create_packet(struct secret_proto *proto, char *data, int datalen) {
    int icmp_len = sizeof(struct icmp);
    int proto_len = sizeof(struct secret_proto);

    char *packet = (char *)calloc(icmp_len + proto_len + datalen, 1);

    if (!packet) {
        fprintf(stderr, "malloc failed\n");
        return packet;
    }

    struct icmp *icmp = (struct icmp *)(packet);

    icmp->icmp_type =  this->dest->ai_family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->icmp_code = 0;
    icmp->icmp_id = 0;
    icmp->icmp_seq = htons(0);

    // cpy data to packet
    memcpy(packet + icmp_len, proto, proto_len);
    memcpy(packet + (icmp_len + proto_len), data, datalen);

    // calculate checksum
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = csum(packet, icmp_len + proto_len + datalen);

    return packet;
}

int icmp_client::prepare_socket() {
    int proto = this->dest->ai_family == AF_INET ? (int)IPPROTO_ICMP : (int)IPPROTO_ICMPV6 ; //cast to int to prevent warning message of enumeral missmatch

    if ((this->sock = socket(this->dest->ai_family, SOCK_RAW, proto)) < 0) {
        perror("socket failed");
        return 1;
    }

    return 0;
}

int icmp_client::prepare_file() {
    if (!access(this->file_name, F_OK) == 0) {
        fprintf(stderr, "file doesn't exist\n");
        return 1;
    }

    this->file = ifstream(this->file_name, ios::binary);

    if (!this->file.is_open()) {
        fprintf(stderr, "cannot open file\n");
        return 1;
    }

    this->file.seekg(0, this->file.end);
    int length = this->file.tellg();
    this->file.seekg(0, this->file.beg);

    return 0;
}

char *icmp_client::get_file_data(int len, int *datalen) {
    char *data = (char *)calloc(len, 1);
    if (!data) {
        fprintf(stderr, "malloc failed\n");
        return data;
    }

    this->file.read(data, len);

    if (this->file)
        *datalen = len;
    else
        *datalen = this->file.gcount();

    return data;
}

//*https://www.geeksforgeeks.org/ping-in-c/
unsigned short csum(char *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}