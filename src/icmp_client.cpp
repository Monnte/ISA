#include "icmp_client.h"

icmp_client::icmp_client() {
    srand(time(NULL));
    this->client_id = rand();
}

icmp_client::~icmp_client() {}

int icmp_client::set_src_dst_ip() {
    char src_name[256];

    struct hostent *src_hp, *dst_hp;

    if (gethostname(src_name, sizeof(src_name)) < 0) {
        fprintf(stderr, "gethostname() error\n");
        return 1;
    }

    if ((src_hp = gethostbyname(src_name)) == NULL) {
        fprintf(stderr, "unknown source: %s\n", src_name);
        return 1;
    }

    this->src_ip = (*(struct in_addr *)src_hp->h_addr);

    if ((dst_hp = gethostbyname(this->dst_host)) == NULL) {                         // try get destination by hostname
        if ((this->dst_ip.s_addr = inet_addr(this->dst_host)) == (in_addr_t)(-1)) { // try get destination by ip adress
            fprintf(stderr, "unknown destination: %s\n", dst_host);
            return 1;
        }
    } else {
        this->dst_ip = (*(struct in_addr *)dst_hp->h_addr);
    }

    return 0;
}

int icmp_client::send_file(char *file_name, char *dst_host) {
    printf("File Name: %s | Adress: %s\n-----------------------------\n", file_name, dst_host);

    this->file_name = file_name;
    this->dst_host = dst_host;

    if (this->set_src_dst_ip())
        return 1;

    if (this->prepare_file())
        return 1;

    if (this->prepare_socket())
        return 1;

    struct sockaddr_in dst;

    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = this->dst_ip.s_addr;
    dst.sin_port = 0;

    // send start packet
    if (send_pkt(&dst, basename(this->file_name), strlen(this->file_name), pkt_type::HEAD))
        return 1;

    // send data
    int max_data_len = ETHERMTU - sizeof(struct ip) - sizeof(struct icmp) - sizeof(struct secret_proto) - AES_BLOCK_SIZE; // HEADERS + PROTOCOLS - reservere block for encrypted data

    while (!file.eof()) {

        int datalen = 0;
        char *data = get_file_data(max_data_len, &datalen);

        if (!data)
            return 1;

        if (datalen == 0) {
            fprintf(stderr, "error while reading file\n");
            return 1;
        }

        if (send_pkt(&dst, data, datalen, pkt_type::DATA))
            return 1;

        free(data);
    }
    this->file.close();

    // send end packet
    if (send_pkt(&dst, basename(this->file_name), strlen(this->file_name), pkt_type::END))
        return 1;

    printf("\nSuccesfully sended file: %s\n", this->file_name);
    return 0;
}

int icmp_client::send_pkt(struct sockaddr_in *dst, char *data, int datalen, int pck_type) {
    static int sequence = 0;

    int dst_addr_len = sizeof(*dst);

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

    int packet_size = sizeof(struct ip) + sizeof(struct icmp) + sizeof(struct secret_proto) + encrypted_data_len;

    int transfered_len = 0;
    if ((transfered_len = sendto(this->sock, packet, packet_size, 0, (struct sockaddr *)dst, dst_addr_len)) < 0) {
        perror("sendto() failed ");
        return 1;
    }

    if (encrypted_data)
        free(encrypted_data);

    if (packet)
        free(packet);

    return 0;
}

char *icmp_client::create_packet(struct secret_proto *proto, char *data, int datalen) {
    int ipv4_len = sizeof(struct ip);
    int icmp_len = sizeof(struct icmp);
    int proto_len = sizeof(struct secret_proto);

    char *packet = (char *)calloc(ipv4_len + icmp_len + proto_len + datalen, 1);

    if (!packet) {
        fprintf(stderr, "malloc failed\n");
        return packet;
    }

    struct ip *ip = (struct ip *)packet;
    struct icmp *icmp = (struct icmp *)(packet + ipv4_len);

    ip->ip_src = this->src_ip;
    ip->ip_dst = this->dst_ip;
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(ipv4_len + icmp_len + proto_len + datalen);
    ip->ip_id = 0;
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;

    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = 0;
    icmp->icmp_seq = htons(0);

    // cpy data to packet
    memcpy(packet + (ipv4_len + icmp_len), (void *)proto, proto_len);
    memcpy(packet + (ipv4_len + icmp_len + proto_len), data, datalen);

    // calculate checksum
    ip->ip_sum = 0;
    ip->ip_sum = csum(packet, ipv4_len);
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = csum(packet + ipv4_len, icmp_len + proto_len + datalen);

    return packet;
}

//*https://www.geeksforgeeks.org/ping-in-c/
unsigned short icmp_client::csum(char *b, int len) {
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

int icmp_client::prepare_socket() {
    const int on = 1;

    if ((this->sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        fprintf(stderr, "socket() error\n");
        return 1;
    }
    if (setsockopt(this->sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr, "setsockopt() error\n");
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