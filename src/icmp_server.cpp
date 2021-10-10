#include "icmp_server.h"

icmp_server::icmp_server() {}

icmp_server::~icmp_server() {}

int icmp_server::init() {
    char *interface;
    char error_message[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    int datalink_type;

    pcap_if_t *interfaces;

    if (pcap_findalldevs(&interfaces, error_message) == -1) {
        fprintf(stderr, "Error: %s\n", error_message);
        return 1;
    }
    interface = interfaces->name;

    if (pcap_lookupnet((interface), &(netp), &(maskp), error_message) == -1) {
        fprintf(stderr, "Error: %s\n", error_message);
        return 1;
    }

    this->device = pcap_open_live(interface, BUFSIZ * 10, 0, 1, error_message);
    if (this->device == NULL) {
        fprintf(stderr, "Error: %s\n", error_message);
        return 1;
    }

    int compile = pcap_compile(this->device, &(fp), (char *)"icmp or icmp6", 0, netp);
    if (compile == -1) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(this->device));
        return 1;
    }

    int setfilter = pcap_setfilter(this->device, &(fp));
    if (setfilter == -1) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(this->device));
        return 1;
    }

    datalink_type = pcap_datalink(this->device);
    if (datalink_type < 0) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(this->device));
        return 1;
    }

    pcap_freealldevs(interfaces);
    pcap_freecode(&(fp));

    return 0;
}

int icmp_server::start() {
    printf("Sever is listening!\n-----------------------------\n");
    if (pcap_loop(this->device, -1, handle_packet, (u_char *)this) < 0) {
        fprintf(stderr, "Error: error occures while capturing packets\n");
        return 1;
    }
    pcap_close(this->device);

    return 0;
}

void handle_packet(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    auto server = (icmp_server *)user;

    struct ether_header *eth_header = (struct ether_header *)pkt_data;
    int ip_version;

    /* Check for ip protocol version */
    switch (ntohs(eth_header->ether_type)) {
    case ETHERTYPE_IP:
        ip_version = 4;
        break;
    case ETHERTYPE_IPV6:
        ip_version = 6;
        break;
    default:
        return;
        break;
    }

    server->handle_data((char *)pkt_data, pkt_header->caplen, ip_version);
}

void icmp_server::handle_data(char *pkt_data, int caplen, int ip_version) {
    int ip_len = ip_version == 4 ? sizeof(struct ip) : sizeof(struct ip6_hdr);
    int icmp_len = sizeof(struct icmp);
    int proto_len = sizeof(struct secret_proto);

    int headers_length = ETH_HLEN + ip_len + icmp_len + proto_len;
    int datalen = caplen - (ETH_HLEN + ip_len + icmp_len + proto_len);

    /* Check if captured length is enough to map on necessary headers + secret_proto */
    if (caplen < headers_length)
        return;

    /* Map data to headers */
    struct icmp *icmp = (struct icmp *)(pkt_data + ETH_HLEN + ip_len);
    struct secret_proto *proto = (struct secret_proto *)(pkt_data + ETH_HLEN + ip_len + icmp_len);

    /* Check if icmp type is request type */
    if (icmp->icmp_type != (ip_version == 4 ? ICMP_ECHO : ICMP6_ECHO_REQUEST)) {
        return;
    }

    /* Check for secret proto name */
    if (strcmp(proto->proto_name, "MNT")) {
        return;
    }

    char *data = (char *)calloc(datalen, 1);
    memcpy(data, pkt_data + headers_length, datalen);

    /* Decrypt gotten data */
    int outlength;
    char *decrypted_data = decrypt_text(data, datalen, &outlength);

    /* Choose action based on packet type */
    switch (proto->type) {
    case pkt_type::HEAD:
        this->new_file(decrypted_data, proto->client_id);
        break;
    case pkt_type::DATA:
        this->file_write(proto->client_id, decrypted_data, proto->datalen, proto->seq);
        break;
    case pkt_type::END:
        this->file_transferd(decrypted_data, proto->client_id);
        break;

    default:
        return;
        break;
    }

    /* Free alocated resources */

    free(data);
    free(decrypted_data);
}

int icmp_server::new_file(char *filename, int ID) {
    struct fileinfo *fileinfo = new struct fileinfo;

    ofstream *file = new ofstream(filename, ios::out | ios::binary);
    if (!file)
        return 1;

    if (!file->is_open()) {
        printf("Failed to open file: %s , file transfer with ID: %d is cancled\n", filename, ID);
        return 1;
    }

    this->connections[ID] = fileinfo;
    this->connections[ID]->file_ptr = file;
    this->connections[ID]->seq = 1;

    printf("Incoming file: %s | Transfer ID: %d\n", filename, ID);
    return 0;
}

int icmp_server::file_write(int ID, char *data, int datalen, int seq) {
    if (this->connections.find(ID) == this->connections.end())
        return 1;

    /* Sequention check for reliable connection */
    if (seq != this->connections[ID]->seq) {
        printf("File transfer with ID: %d was coruptted ending accepting packets from this transfer\n", ID);
        this->transfer_error(ID);
        return 1;
    }
    this->connections[ID]->seq++;

    /* To prevent packet loosing we need to reduce I/O calls so we accumulate data in memory */
    this->connections[ID]->data.insert(this->connections[ID]->data.end(), data, data + datalen);

    int vec_data_len = this->connections[ID]->data.size();
    if (vec_data_len > 1000000) /* Write acuumulated data over 1MB */
    {
        this->connections[ID]->file_ptr->write(this->connections[ID]->data.data(), vec_data_len);
        this->connections[ID]->data.clear();
    }

    return 0;
}

int icmp_server::file_transferd(char *filename, int ID) {
    if (this->connections.find(ID) == this->connections.end())
        return 1;

    /* Write the remaining acummulated data to the file */
    int vec_data_len = this->connections[ID]->data.size();
    this->connections[ID]->file_ptr->write(this->connections[ID]->data.data(), vec_data_len);
    this->connections[ID]->data.clear();

    this->connections[ID]->file_ptr->close();

    delete this->connections[ID]->file_ptr;
    delete this->connections[ID];

    this->connections.erase(ID);

    printf("Succesfully transfered file: %s  | Transfer ID: %d\n", filename, ID);
    return 0;
}

int icmp_server::transfer_error(int ID) {
    if (this->connections.find(ID) == this->connections.end())
        return 1;

    delete this->connections[ID]->file_ptr;
    delete this->connections[ID];

    this->connections.erase(ID);

    return 0;
}

void icmp_server::exit_server() {
    /* Clear corrupted and abadoned files */
    for (auto const &x : this->connections) {
        printf("File transfer with ID: %d is closing\n", x.first);
        this->connections[x.first]->data.clear();
        this->connections[x.first]->file_ptr->close();

        delete this->connections[x.first]->file_ptr;
        delete this->connections[x.first];
    }
    this->connections.clear();

    pcap_breakloop(this->device);
    pcap_close(this->device);
}