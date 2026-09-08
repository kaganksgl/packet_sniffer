#define _DEFAULT_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define exit_with_error(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)

typedef struct {
    uint8_t t_protocol;
    struct in_addr source_ip;
    struct in_addr dest_ip;
    uint8_t has_source_ip;
    uint8_t has_dest_ip;
    const char *source_ip_text;
    const char *dest_ip_text;
    uint16_t source_port;
    uint16_t dest_port;
    char *source_if_name;
    char *dest_if_name;
    uint8_t source_mac[6];
    uint8_t dest_mac[6];

} packet_filter_t;

struct sockaddr_in source_addr, dest_addr;

void get_mac(char *if_name, packet_filter_t *packet_filter, char *if_type) {
    int fd;
    struct ifreq ifr;

    if (strlen(if_name) >= IF_NAMESIZE) {
        fprintf(stderr, "interface name too long: %s\n", if_name);
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {exit_with_error("failed to create socket for SIOCGIFHWADDR");}


    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_name, IF_NAMESIZE-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        fprintf(stderr, "failed to get MAC address of interface %s: %s\n", if_name, strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(fd);

    if (strcmp(if_type, "source") == 0) {
        memcpy(packet_filter->source_mac, ifr.ifr_hwaddr.sa_data, 6);
    } else {
        memcpy(packet_filter->dest_mac, ifr.ifr_hwaddr.sa_data, 6);
    }
    
}


void usage(const char *program) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --sip ADDR      only packets from this IPv4 address\n"
        "  --dip ADDR      only packets to this IPv4 address\n"
        "  --sport PORT    only packets from this port\n"
        "  --dport PORT    only packets to this port\n"
        "  --sif NAME      only packets whose source MAC is this interface's\n"
        "  --dif NAME      only packets whose destination MAC is this interface's\n"
        "  --tcp           only TCP packets\n"
        "  --udp           only UDP packets\n"
        "  --logfile PATH  where to write the capture (default sniffer_log.txt)\n"
        "  --help          show this message\n"
        "\nNeeds CAP_NET_RAW: run under sudo, or grant it once with 'make setcap'.\n"
        "Capture only traffic you are authorised to monitor.\n",
        program);
}

void parse_ip(const char *text, const char *option, struct in_addr *out, uint8_t *present) {
    if (inet_pton(AF_INET, text, out) != 1) {
        fprintf(stderr, "%s must be a dotted IPv4 address, got '%s'\n", option, text);
        exit(EXIT_FAILURE);
    }
    *present = 1;
}

uint16_t parse_port(const char *text, const char *option) {
    char *end = NULL;
    long value = strtol(text, &end, 10);

    if (end == text || *end != '\0' || value < 1 || value > 65535) {
        fprintf(stderr, "%s must be a port between 1 and 65535, got '%s'\n", option, text);
        exit(EXIT_FAILURE);
    }
    return (uint16_t)value;
}

uint8_t maccmp(uint8_t *mac1, uint8_t *mac2) {
    for (uint8_t i = 0; i < 6; i++) {
        if (mac1[i] != mac2[i]) {return 0;}
    }
    return 1;
}

void log_eth_headers(struct ethhdr *eth, FILE *lf) {
    fprintf(lf, "\nEthernet Header\n");
    fprintf(lf, "\t-Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(lf, "\t-Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(lf, "\t-Protocol : %d\n", ntohs(eth->h_proto));
}

void log_ip_headers(struct iphdr *ip, FILE *lf) {
    fprintf(lf, "\nIP Header\n");
    fprintf(lf, "\t-Version : %d\n", (uint32_t)ip->version);
    fprintf(lf, "\t-Internet Header Length : %d bytes \n", (uint32_t)(ip->ihl * 4));
    fprintf(lf, "\t-Type of Service : %d\n", (uint32_t)ip->tos);
    fprintf(lf, "\t-Total Length : %d\n", ntohs(ip->tot_len));
    fprintf(lf, "\t-Identification : %d\n", ntohs(ip->id));
    fprintf(lf, "\t-Time to Live : %d\n", (uint32_t)ip->ttl);
    fprintf(lf, "\t-Protocol : %d\n", (uint32_t)ip->protocol);
    fprintf(lf, "\t-Header Checksum : %d\n", ntohs(ip->check));
    fprintf(lf, "\t-Source IP : %s\n", inet_ntoa(source_addr.sin_addr));
    fprintf(lf, "\t-Destination : %s\n", inet_ntoa(dest_addr.sin_addr));
}

void log_tcp_headers(struct tcphdr *tcp, FILE *lf) {
    fprintf(lf, "\nTCP Header\n");
    fprintf(lf, "\t-Source Port : %d\n", ntohs(tcp->source));
    fprintf(lf, "\t-Destination Port : %u\n", ntohs(tcp->dest));
    fprintf(lf, "\t-Sequence Number : %u\n", ntohl(tcp->seq));
    fprintf(lf, "\t-Acknowledgement Number : %u\n", ntohl(tcp->ack_seq));
    fprintf(lf, "\t-Header Length in Bytes : %d\n", (uint32_t)tcp->doff * 4);
    fprintf(lf, "\t ------- Flags ---------\n");
    fprintf(lf, "\t-Urgent Flag : %d\n", (uint32_t)tcp->urg);
    fprintf(lf, "\t-Acknowledgement Flag : %d\n", (uint32_t)tcp->ack);
    fprintf(lf, "\t-Push Flag : %d\n", (uint32_t)tcp->psh);
    fprintf(lf, "\t-Reset Flag : %d\n", (uint32_t)tcp->rst);
    fprintf(lf, "\t-Synchronise Flag : %d\n", (uint32_t)tcp->syn);
    fprintf(lf, "\t-Finish Flag : %d\n", (uint32_t)tcp->fin);
    fprintf(lf, "\t-Window Size : %d\n", ntohs(tcp->window));
    fprintf(lf, "\t-Checksum : %d\n", ntohs(tcp->check));
    fprintf(lf, "\t-Urgent pointer : %d\n", ntohs(tcp->urg_ptr));
}

void log_udp_headers(struct udphdr *udp, FILE *lf) {
    fprintf(lf, "\nUDP Header\n");
    fprintf(lf, "\t-Source Port : %d\n", ntohs(udp->source));
    fprintf(lf, "\t-Destination Port : %u\n", ntohs(udp->dest));
    fprintf(lf, "\t-UDP Length : %u\n", ntohs(udp->len));
    fprintf(lf, "\t-UDP Checksum : %u\n", ntohs(udp->check));
}

void log_payload(uint8_t *buffer, int bufflen, int iphdrlen, uint8_t t_protocol, FILE *lf, struct tcphdr *tcp) {
    int t_protocol_header_size = (int)sizeof(struct udphdr);
    if (t_protocol == IPPROTO_TCP) {
        t_protocol_header_size = (uint32_t)tcp->doff * 4;
    }

    int header_total = (int)sizeof(struct ethhdr) + iphdrlen + t_protocol_header_size;
    
    if (header_total < 0 || header_total > bufflen) {
        fprintf(lf, "\nData\n(no payload)\n");
        return;
    }

    uint8_t *packet_data = buffer + header_total;
    int remaining_data_size = bufflen - header_total;

    fprintf(lf, "\nData\n");
    for (int i = 0; i < remaining_data_size; i++) {
        if (i != 0 && i % 16 == 0) {
            fprintf(lf, "\n");
        }
        fprintf(lf, " %02X ", packet_data[i]);
    }
    fprintf(lf, "\n");
}

int filter_port(uint16_t sport, uint16_t dport, packet_filter_t *filter) {
    if (filter->source_port != 0 && filter->source_port != sport) {
        return 0;
    }
    if (filter->dest_port != 0 && filter->dest_port != dport) {
        return 0;
    }
    return 1;
}

int filter_ip(packet_filter_t *filter, struct iphdr *ip) {
    if (filter->has_source_ip && ip->saddr != filter->source_ip.s_addr) {
        return 0;
    }

    if (filter->has_dest_ip && ip->daddr != filter->dest_ip.s_addr) {
        return 0;
    }

    return 1;
}

void process_packet(uint8_t *buffer, int bufflen, packet_filter_t *packet_filter, FILE *lf) {
    int iphdrlen;

    if (bufflen < (int)sizeof(struct ethhdr)) {return;}

    struct ethhdr *eth = (struct ethhdr*)(buffer);

    if (ntohs(eth->h_proto) != 0x0800) {
        return;
    }

    if (packet_filter->source_if_name != NULL && maccmp(packet_filter->source_mac, eth->h_source) == 0) {
        return;
    }

    if (packet_filter->dest_if_name != NULL && maccmp(packet_filter->dest_mac, eth->h_dest) == 0) {
        return;
    }

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = ip->ihl * 4;

    if (ip->version != 4 || ip->ihl < 5 || bufflen < (int)sizeof(struct ethhdr) + iphdrlen) {return;}

    /* Short frames are padded up to 60 bytes on the wire. Trust the IP total
       length when it is present and fits, so padding is not logged as payload.
       Offloaded packets report 0 or more than was captured; leave those alone. */
    int ip_total = ntohs(ip->tot_len);
    if (ip_total >= iphdrlen && (int)sizeof(struct ethhdr) + ip_total <= bufflen) {
        bufflen = (int)sizeof(struct ethhdr) + ip_total;
    }

    memset(&source_addr, 0, sizeof(source_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    source_addr.sin_addr.s_addr = ip->saddr;
    dest_addr.sin_addr.s_addr = ip->daddr;


    if (filter_ip(packet_filter, ip) == 0) {
        return;
    }

    if (packet_filter->t_protocol != 0 && ip->protocol != packet_filter->t_protocol) {
        return;
    }
    struct tcphdr *tcp  = NULL;
    struct udphdr *udp = NULL;
    int transport_offset = (int)sizeof(struct ethhdr) + iphdrlen;

    /* A truncated or fragmented frame can stop before the transport header.
       Without these checks the header is read from whatever the shared buffer
       still holds from the previous packet. */
    if (ip->protocol == IPPROTO_TCP) {
        if (bufflen < transport_offset + (int)sizeof(struct tcphdr)) {return;}
        tcp = (struct tcphdr*)(buffer + transport_offset);
        if (tcp->doff < 5) {return;}
        if (filter_port(ntohs(tcp->source), ntohs(tcp->dest), packet_filter) == 0) {
            return;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        if (bufflen < transport_offset + (int)sizeof(struct udphdr)) {return;}
        udp = (struct udphdr*)(buffer + transport_offset);
        if (filter_port(ntohs(udp->source), ntohs(udp->dest), packet_filter) == 0) {
            return;
        }
    } else {
        return;
    }

    log_eth_headers(eth, lf);
    log_ip_headers(ip, lf);
    if (tcp != NULL) {
        log_tcp_headers(tcp, lf);
    }
    if (udp != NULL) {
        log_udp_headers(udp, lf);
    }
    
    log_payload(buffer, bufflen, iphdrlen, ip->protocol, lf, tcp);
}


int main(int argc, char **argv) {
    int c;

    setvbuf(stdout, NULL, _IOLBF, 0);

    char log[225] = {0};
    FILE *logfile = NULL;


    packet_filter_t packet_filter = {0};

    struct sockaddr_storage saddr;
    int sockfd, bufflen;
    socklen_t saddr_len;

    uint8_t *buffer = (uint8_t*) malloc(65536);
    if (buffer == NULL) {exit_with_error("failed to allocate packet buffer");}
    memset(buffer, 0, 65536);

    while (1) {
        static struct option long_options[] = {
            {"sip", required_argument, NULL, 's'},
            {"dip", required_argument, NULL, 'd'},
            {"sport", required_argument, NULL, 'p'},
            {"dport", required_argument, NULL, 'o'},
            {"sif", required_argument, NULL, 'i'},
            {"dif", required_argument, NULL, 'g'},
            {"logfile", required_argument, NULL, 'f'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {"help", no_argument, NULL, 'h'},
            {0,0,0,0}
        };
        
        c = getopt_long(argc, argv, "htus:d:p:o:i:g:f:", long_options, NULL);
        
        if (c==-1) {
            break;
        }

        switch (c) {
            case 't': {packet_filter.t_protocol = IPPROTO_TCP; break;}
            case 'u': {packet_filter.t_protocol = IPPROTO_UDP; break;}
            case 'p': {packet_filter.source_port = parse_port(optarg, "--sport"); break;}
            case 'o': {packet_filter.dest_port = parse_port(optarg, "--dport"); break;}
            case 's': {
                parse_ip(optarg, "--sip", &packet_filter.source_ip, &packet_filter.has_source_ip);
                packet_filter.source_ip_text = optarg;
                break;
            }
            case 'd': {
                parse_ip(optarg, "--dip", &packet_filter.dest_ip, &packet_filter.has_dest_ip);
                packet_filter.dest_ip_text = optarg;
                break;
            }
            case 'i': {packet_filter.source_if_name = optarg; break;}
            case 'g': {packet_filter.dest_if_name = optarg; break;}
            case 'f': {
                if (snprintf(log, sizeof(log), "%s", optarg) >= (int)sizeof(log)) {
                    fprintf(stderr, "--logfile path is too long (max %zu characters)\n", sizeof(log) - 1);
                    exit(EXIT_FAILURE);
                }
                break;
            }
            case 'h': {usage(argv[0]); exit(EXIT_SUCCESS);}
            default: {usage(argv[0]); exit(EXIT_FAILURE);}
        }
        
        
    }
    
    printf("t_protocol: %d\n", packet_filter.t_protocol);
    printf("source_port: %d\n", packet_filter.source_port);
    printf("dest_port: %d\n", packet_filter.dest_port);
    printf("source_ip: %s\n", packet_filter.source_ip_text ? packet_filter.source_ip_text : "any");
    printf("dest_ip: %s\n", packet_filter.dest_ip_text ? packet_filter.dest_ip_text : "any");
    printf("source interface: %s\n", packet_filter.source_if_name ? packet_filter.source_if_name : "any");
    printf("dest interface: %s\n", packet_filter.dest_if_name ? packet_filter.dest_if_name : "any");
    printf("log file: %s\n", log);

    if (strlen(log) == 0) {
        strcpy(log, "sniffer_log.txt");
    }

    /* O_NOFOLLOW stops a planted symlink redirecting the log somewhere else when
       the sniffer is run under sudo, and 0600 keeps captured payloads private. */
    int logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (logfd < 0) {
        exit_with_error("failed to open log file");
    }

    logfile = fdopen(logfd, "w");
    if (!logfile) {
        close(logfd);
        exit_with_error("failed to open log file");
    }

    /* An existing log keeps its old mode, so tighten it either way. */
    if (fchmod(logfd, S_IRUSR | S_IWUSR) != 0) {
        exit_with_error("failed to restrict log file permissions");
    }

    if (packet_filter.source_if_name != NULL) {
        get_mac(packet_filter.source_if_name, &packet_filter, "source");
    }

    if (packet_filter.dest_if_name != NULL) {
        get_mac(packet_filter.dest_if_name, &packet_filter, "dest");
    }

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        fprintf(stderr, "failed to create raw socket: %s\n", strerror(errno));
        fprintf(stderr, "capturing needs CAP_NET_RAW: run under sudo, or grant it once with 'make setcap'.\n");
        exit(EXIT_FAILURE);
    }
    
    while (1) {
        saddr_len = sizeof saddr;
        bufflen = recvfrom(sockfd, buffer, 65536, 0, (struct sockaddr *)&saddr, &saddr_len);
        if (bufflen < 0) {
            if (errno == EINTR) {continue;}
            exit_with_error("failed to read from socket");
        }
        process_packet(buffer, bufflen, &packet_filter, logfile);
        fflush(logfile);
    }
    
}
