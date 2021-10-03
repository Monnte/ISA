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

    this->device = pcap_open_live(interface, BUFSIZ, 1, 1000, error_message);
    if (this->device == NULL) {
        fprintf(stderr, "Error: %s\n", error_message);
        return 1;
    }

    int compile = pcap_compile(this->device, &(fp), (char *)"icmp", 0, netp);
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

    if (pcap_loop(this->device, -1, handle_packet, (u_char *)this) < 0) {
        fprintf(stderr, "Error: error occures while capturing packets\n");
        return 1;
    }
    pcap_close(this->device);

    return 0;
}

void handle_packet(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    auto server = (icmp_server *)user;

    int ipv4_len = sizeof(struct ip);
    int icmp_len = sizeof(struct icmp);
    int proto_len = sizeof(struct secret_proto);

    int headers_length = ETH_HLEN + ipv4_len + icmp_len + proto_len;
    int datalen = pkt_header->caplen - (ETH_HLEN + ipv4_len + icmp_len + proto_len);

    if ((int)pkt_header->caplen < headers_length)
        return;

    struct ip *ip = (struct ip *)pkt_data + ETH_HLEN;
    struct icmp *icmp = (struct icmp *)(pkt_data + ETH_HLEN + ipv4_len);
    struct secret_proto *proto = (struct secret_proto *)(pkt_data + ETH_HLEN + ipv4_len + icmp_len);

    if (strcmp(proto->proto_name, "MNT"))
        return;

    char *data = (char *)calloc(datalen, 1);
    memcpy(data, pkt_data + headers_length, datalen);

    int outlength;
    char *decrypted_data = decrypt_text(data, datalen, &outlength);

    switch (proto->type) {
    case pkt_type::HEAD:
        server->new_file(decrypted_data, proto->client_id);
        break;
    case pkt_type::DATA:
        server->file_write(proto->client_id, decrypted_data, proto->datalen, proto->seq);
        break;
    case pkt_type::END:
        server->file_transferd(decrypted_data, proto->client_id);
        break;

    default:
        return;
        break;
    }

    free(data);
    free(decrypted_data);
}

int icmp_server::new_file(char *filename, int ID) {
    struct fileinfo *fileinfo = new struct fileinfo;

    ofstream *file = new ofstream(filename, ios::out | ios::binary);
    if (!file)
        return 1;

    this->connections[ID] = fileinfo;
    this->connections[ID]->file_ptr = file;
    this->connections[ID]->seq = 1;

    if (!file->is_open())
        return 1;

    printf("Incoming file: %s | Transfer ID: %d\n", filename, ID);
    return 0;
}

int icmp_server::file_write(int ID, char *data, int datalen, int seq) {
    if (this->connections.find(ID) == this->connections.end())
        return 1;

    if (seq != this->connections[ID]->seq) {
        printf("File transfer with ID: %d was coruptted ending accepting packets from this transfer\n", ID);
        this->file_corrupted(ID);
        return 1;
    }

    this->connections[ID]->seq++;
    this->connections[ID]->file_ptr->write(data, datalen);
    this->connections[ID]->file_ptr->flush();
    return 0;
}

int icmp_server::file_transferd(char *filename, int ID) {
    if (this->connections.find(ID) == this->connections.end())
        return 1;

    this->connections[ID]->file_ptr->close();

    delete this->connections[ID]->file_ptr;
    delete this->connections[ID];

    this->connections.erase(ID);

    printf("Succesfully transfered file: %s  | Transfer ID: %d\n", filename, ID);
    return 0;
}

int icmp_server::file_corrupted(int ID) {
    if (this->connections.find(ID) == this->connections.end())
        return 1;

    this->connections[ID]->file_ptr->clear();
    this->connections[ID]->file_ptr->write("corrupted file", 14);
    this->connections[ID]->file_ptr->flush();
    this->connections[ID]->file_ptr->close();

    delete this->connections[ID]->file_ptr;
    delete this->connections[ID];

    this->connections.erase(ID);

    return 0;
}
void icmp_server::exit_server() {

    // clear corrupted and abadoned files
    for (auto const &x : this->connections) {
        printf("File transfer with ID: %d is closing\n", x.first);
        this->connections[x.first]->file_ptr->clear();
        this->connections[x.first]->file_ptr->close();

        delete this->connections[x.first]->file_ptr;
        delete this->connections[x.first];
    }
    this->connections.clear();

    pcap_breakloop(this->device);
    pcap_close(this->device);
}