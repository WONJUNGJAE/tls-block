#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

typedef struct {
    uint8_t addr[6];
} Mac;

struct EthHdr {
    Mac dmac;
    Mac smac;
    uint16_t type;
};

struct IpHdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t sum;
    uint32_t sip;
    uint32_t dip;
};

struct TcpHdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};

struct PseudoHdr {
    uint32_t sip;
    uint32_t dip;
    uint8_t zero;
    uint8_t proto;
    uint16_t tcp_len;
};

#define TH_RST 0x04
#define TH_ACK 0x10
#define ETH_TYPE_IP 0x0800
#define IP_PROTO_TCP 6

pcap_t* handle;
char* pattern;
uint8_t my_mac[6];
int rawSocket = -1;

uint16_t checksum(void* data, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void get_my_mac(const char* interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
}

char* parse_sni(const uint8_t* data, uint16_t data_size) {
    if (data_size < 5) return NULL;
    if (data[0] != 0x16) return NULL;

    if (data_size < 9) return NULL;
    if (data[5] != 0x01) return NULL;

    const uint8_t* p = data + 9;
    const uint8_t* end = data + data_size;

    if (p + 2 > end) return NULL;
    p += 2;

    if (p + 32 > end) return NULL;
    p += 32;

    if (p + 1 > end) return NULL;
    uint8_t session_id_len = *p;
    p += 1;
    if (p + session_id_len > end) return NULL;
    p += session_id_len;

    if (p + 2 > end) return NULL;
    uint16_t cipher_len = (p[0] << 8) | p[1];
    p += 2;
    if (p + cipher_len > end) return NULL;
    p += cipher_len;

    if (p + 1 > end) return NULL;
    uint8_t comp_len = *p;
    p += 1;
    if (p + comp_len > end) return NULL;
    p += comp_len;

    if (p + 2 > end) return NULL;
    uint16_t ext_total_len = (p[0] << 8) | p[1];
    p += 2;

    const uint8_t* ext_end = p + ext_total_len;
    if (ext_end > end) return NULL;

    while (p < ext_end) {
        if (p + 2 > ext_end) return NULL;
        uint16_t ext_type = (p[0] << 8) | p[1];
        p += 2;

        if (p + 2 > ext_end) return NULL;
        uint16_t ext_len = (p[0] << 8) | p[1];
        p += 2;

        if (ext_type == 0x0000) {
            if (p + 2 > ext_end) return NULL;
            p += 2;

            if (p + 1 > ext_end) return NULL;
            if (*p != 0x00) return NULL;
            p += 1;

            if (p + 2 > ext_end) return NULL;
            uint16_t name_len = (p[0] << 8) | p[1];
            p += 2;

            if (p + name_len > ext_end) return NULL;
            char* sni = (char*)malloc(name_len + 1);
            memcpy(sni, p, name_len);
            sni[name_len] = '\0';
            return sni;

        } else {
            p += ext_len;
        }
    }

    return NULL;
}

void send_backward(const u_char* org_packet, uint16_t data_size) {
    int buf_size = sizeof(struct EthHdr) + sizeof(struct IpHdr) + sizeof(struct TcpHdr);
    uint8_t buf[buf_size];
    memset(buf, 0, buf_size);

    struct EthHdr* org_eth = (struct EthHdr*)org_packet;
    struct IpHdr* org_ip = (struct IpHdr*)(org_packet + sizeof(struct EthHdr));
    struct TcpHdr* org_tcp = (struct TcpHdr*)(org_packet + sizeof(struct EthHdr) + sizeof(struct IpHdr));

    struct EthHdr* new_eth = (struct EthHdr*)buf;
    struct IpHdr* new_ip = (struct IpHdr*)(buf + sizeof(struct EthHdr));
    struct TcpHdr* new_tcp = (struct TcpHdr*)(buf + sizeof(struct EthHdr) + sizeof(struct IpHdr));

    memcpy(new_eth->dmac.addr, org_eth->smac.addr, 6);
    memcpy(new_eth->smac.addr, my_mac, 6);
    new_eth->type = org_eth->type;

    new_ip->vhl = org_ip->vhl;
    new_ip->tos = 0;
    new_ip->len = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    new_ip->id = htons(rand() & 0xFFFF);
    new_ip->off = 0;
    new_ip->ttl = 128;
    new_ip->proto = IP_PROTO_TCP;
    new_ip->sum = 0;
    new_ip->sip = org_ip->dip;
    new_ip->dip = org_ip->sip;

    new_tcp->sport = org_tcp->dport;
    new_tcp->dport = org_tcp->sport;
    new_tcp->seq = org_tcp->ack;
    new_tcp->ack = htonl(ntohl(org_tcp->seq) + data_size);
    new_tcp->off = (sizeof(struct TcpHdr) / 4) << 4;
    new_tcp->flags = TH_RST | TH_ACK;
    new_tcp->win = org_tcp->win;
    new_tcp->sum = 0;
    new_tcp->urp = 0;

    new_ip->sum = checksum(new_ip, sizeof(struct IpHdr));

    struct PseudoHdr pseudo;
    pseudo.sip = new_ip->sip;
    pseudo.dip = new_ip->dip;
    pseudo.zero = 0;
    pseudo.proto = IP_PROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct TcpHdr));

    uint8_t tcp_buf[sizeof(struct PseudoHdr) + sizeof(struct TcpHdr)];
    memcpy(tcp_buf, &pseudo, sizeof(struct PseudoHdr));
    memcpy(tcp_buf + sizeof(struct PseudoHdr), new_tcp, sizeof(struct TcpHdr));
    new_tcp->sum = checksum(tcp_buf, sizeof(tcp_buf));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = new_tcp->dport;
    dest.sin_addr.s_addr = new_ip->dip;

    sendto(rawSocket,
           buf + sizeof(struct EthHdr),
           buf_size - sizeof(struct EthHdr),
           0,
           (struct sockaddr*)&dest,
           sizeof(dest));

    printf("Backward RST 전송 완료!\n");
}

void send_forward(const u_char* org_packet, uint16_t data_size) {
    int buf_size = sizeof(struct EthHdr) + sizeof(struct IpHdr) + sizeof(struct TcpHdr);
    uint8_t buf[buf_size];
    memset(buf, 0, buf_size);

    struct EthHdr* org_eth = (struct EthHdr*)org_packet;
    struct IpHdr* org_ip = (struct IpHdr*)(org_packet + sizeof(struct EthHdr));
    struct TcpHdr* org_tcp = (struct TcpHdr*)(org_packet + sizeof(struct EthHdr) + sizeof(struct IpHdr));

    struct EthHdr* new_eth = (struct EthHdr*)buf;
    struct IpHdr* new_ip = (struct IpHdr*)(buf + sizeof(struct EthHdr));
    struct TcpHdr* new_tcp = (struct TcpHdr*)(buf + sizeof(struct EthHdr) + sizeof(struct IpHdr));

    memcpy(new_eth->dmac.addr, org_eth->dmac.addr, 6);
    memcpy(new_eth->smac.addr, my_mac, 6);
    new_eth->type = org_eth->type;

    new_ip->vhl = org_ip->vhl;
    new_ip->tos = 0;
    new_ip->len = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    new_ip->id = htons(rand() & 0xFFFF);
    new_ip->off = 0;
    new_ip->ttl = org_ip->ttl;
    new_ip->proto = IP_PROTO_TCP;
    new_ip->sum = 0;
    new_ip->sip = org_ip->sip;
    new_ip->dip = org_ip->dip;

    new_tcp->sport = org_tcp->sport;
    new_tcp->dport = org_tcp->dport;
    new_tcp->seq = htonl(ntohl(org_tcp->seq) + data_size);
    new_tcp->ack = org_tcp->ack;
    new_tcp->off = (sizeof(struct TcpHdr) / 4) << 4;
    new_tcp->flags = TH_RST | TH_ACK;
    new_tcp->win = org_tcp->win;
    new_tcp->sum = 0;
    new_tcp->urp = 0;

    new_ip->sum = checksum(new_ip, sizeof(struct IpHdr));

    struct PseudoHdr pseudo;
    pseudo.sip = new_ip->sip;
    pseudo.dip = new_ip->dip;
    pseudo.zero = 0;
    pseudo.proto = IP_PROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct TcpHdr));

    uint8_t tcp_buf[sizeof(struct PseudoHdr) + sizeof(struct TcpHdr)];
    memcpy(tcp_buf, &pseudo, sizeof(struct PseudoHdr));
    memcpy(tcp_buf + sizeof(struct PseudoHdr), new_tcp, sizeof(struct TcpHdr));
    new_tcp->sum = checksum(tcp_buf, sizeof(tcp_buf));

    if (pcap_sendpacket(handle, buf, buf_size) != 0)
        printf("Forward 전송 실패: %s\n", pcap_geterr(handle));
    else
        printf("Forward RST 전송 완료!\n");
}

void callback(u_char* user,
              const struct pcap_pkthdr* header,
              const u_char* packet) {

    (void)user;
    (void)header;

    struct EthHdr* eth = (struct EthHdr*)packet;
    if (ntohs(eth->type) != ETH_TYPE_IP) return;

    struct IpHdr* ip = (struct IpHdr*)(packet + sizeof(struct EthHdr));
    if (ip->proto != IP_PROTO_TCP) return;

    struct TcpHdr* tcp = (struct TcpHdr*)(packet + sizeof(struct EthHdr) + sizeof(struct IpHdr));
    if (ntohs(tcp->dport) != 443) return;

    uint16_t data_size = ntohs(ip->len) - sizeof(struct IpHdr) - sizeof(struct TcpHdr);
    if (data_size == 0) return;

    uint8_t* data = (uint8_t*)tcp + sizeof(struct TcpHdr);

    char* sni = parse_sni(data, data_size);
    if (sni == NULL) return;

    printf("SNI 발견: %s\n", sni);

    if (strstr(sni, pattern) == NULL) {
        free(sni);
        return;
    }
    free(sni);

    printf("차단 대상 발견! 차단 시작!\n");
    send_backward(packet, data_size);
    send_forward(packet, data_size);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("사용법: %s <interface> <server name>\n", argv[0]);
        printf("예시:   %s enp0s3 naver.com\n", argv[0]);
        return 1;
    }

    char* interface = argv[1];
    pattern = argv[2];

    get_my_mac(interface);

    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawSocket < 0) {
        perror("raw socket 생성 실패");
        return 1;
    }
    int one = 1;
    setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        printf("pcap 열기 실패: %s\n", errbuf);
        return 1;
    }

    printf("캡처 시작! interface=%s server=%s\n", interface, pattern);
    pcap_loop(handle, 0, callback, NULL);

    close(rawSocket);
    pcap_close(handle);
    return 0;
}
