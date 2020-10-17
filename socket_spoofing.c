#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

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

int main() {
    struct ip ip;
    struct icmp icmp;
    int sd;
    const int on = 1;
    struct sockaddr_in sin;
    u_char *packet;
    packet = (u_char *)malloc(60);
    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = htons(60);
    ip.ip_id = htons(12830);
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_ICMP;
    ip.ip_sum = 0x0;
    ip.ip_src.s_addr = inet_addr("172.17.14.174");
    ip.ip_dst.s_addr = inet_addr("172.17.14.169");
    ip.ip_sum = in_cksum((u_short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));

    icmp.icmp_type = ICMP_ECHO;
    icmp.icmp_code = 0;
    icmp.icmp_cksum = 0;
    icmp.icmp_cksum = in_cksum((u_short *)&icmp, 8);
    memcpy(packet + 20, &icmp, 8);

    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }

    // no need for IP header, we prepared
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // specify a dest for kernel for Layer I
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;

    if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
    printf("send %s -> %s\n", strdup(inet_ntoa(ip.ip_src)), strdup(inet_ntoa(ip.ip_dst)));
}
















