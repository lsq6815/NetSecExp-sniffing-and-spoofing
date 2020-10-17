#include "data_format.h"
#include "pdu_struct.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_BYTE_TO_CAP 2048
#define COL_PER_ROW 32
#define FAILURE -1

u_short in_cksum(u_short *addr, int len) {
    int nleft = len;
    int sum = 0;
    u_short *w = addr;
    u_short answer = 0;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

/* Callback function to process packet captured */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
    int *counter = (int *)arg;

    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->caplen);

    struct ether_header *ether = (struct ether_header *)packet;
    if (ntohs(ether->ether_type) != ETHER_TYPE_IP4) return;

    struct ip *ip = (struct ip *)(packet + 14);

    if (ip->ip_p != IPPROTO_ICMP) return;
    
    struct icmp *icmp = (struct icmp *)(packet + 14 + ip->ip_hl * 4);

    if (icmp->icmp_type != ICMP_ECHO) return;

    // exchange ip addr
    in_addr_t tmp_net = ip->ip_src.s_addr;
    ip->ip_src.s_addr = ip->ip_dst.s_addr;
    ip->ip_dst.s_addr = tmp_net;
    // calculate check sum
    ip->ip_sum = 0x0;
    ip->ip_sum = in_cksum((u_short *)&ip, sizeof(ip));
    // change type to reply
    icmp->icmp_type = ICMP_ECHOREPLY;
    // calculate check sum
    icmp->icmp_cksum = 0x0;
    icmp->icmp_cksum = in_cksum((u_short *)&icmp, 8);
    
    int sd;
    const int on = 1;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip->ip_dst.s_addr;

    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if ((setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    if ((sendto(sd, packet + 14, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("Spoofing ICMP REPLY %s -> %s", strdup(inet_ntoa(ip->ip_src)), strdup(inet_ntoa(ip->ip_src)));
}


int main(int argc, char *argv[]) {
    int i = 0, count = 0;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = NULL;

    // 1. find devices
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    pcap_if_t *devices;
    pcap_findalldevs(&devices, errbuf);
    device = devices->name;

    // 2. detect net and mask
    bpf_u_int32 net, mask;
    pcap_lookupnet(device, &net, &mask, errbuf); 

    // 3. open device
    handle = pcap_open_live(device, MAX_BYTE_TO_CAP, 1, 1000, errbuf);
    // 4. complie filter
    struct bpf_program fp;
    pcap_compile(handle, &fp, "icmp", 0, net);

    // 5. install filter
    pcap_setfilter(handle, &fp);

    // 6. capture file
    pcap_loop(handle, 100, processPacket, (u_char *)&count);
    printf("%d packet(s) captured\n", count);
}




















