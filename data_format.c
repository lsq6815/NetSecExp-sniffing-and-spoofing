#include "data_format.h"
#include "pdu_struct.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

c_str etherHostToStr(const u_char *host) {
    // use char array, no need for NBO convert
    c_str result = (c_str)calloc(ETHER_ADDR_LEN * 2 + 5 + 1, sizeof(char));
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", 
            host[0],host[1],host[2],host[3],host[4],host[5]
    );
    return result;
}

const c_str etherType(u_short ether_type) {
    switch (ntohs(ether_type)) {
        case ETHER_TYPE_IP4        : return "IPv4";
        case ETHER_TYPE_IP6        : return "IPv6";
        case ETHER_TYPE_ARP        : return "ARP";
        case ETHER_TYPE_RARP       : return "RARP";
        case ETHER_TYPE_ETHER_TALK : return "EtherTalk";
        case ETHER_TYPE_PPP        : return "PPP";
        case ETHER_TYPE_SNMP       : return "SNMP";
        default: return "unknown protocol";
    }
}

c_str ipv4AddrToStr(struct in_addr addr) {
    return strdup(inet_ntoa(addr));
}

const c_str ipv4Type(u_char protocol) {
    switch (protocol) {
        case IPPROTO_ICMP : return "ICMP";
        case IPPROTO_IGMP : return "IGMP";
        case IPPROTO_TCP  : return "TCP";
        case IPPROTO_EGP  : return "EGP";
        case IPPROTO_UDP  : return "UDP";
        default:
            return "unknown protocol";
    }
}


const c_str icmpType(u_char type) {
    switch (type) {
        case ICMP_ECHOREPLY:
            return "ECHO REPLY";
        case ICMP_ECHO:
            return "ECHO REQUEST";
        case ICMP_TIMXCEED:
            return "TIME EXCEEDED";
        case ICMP_DEST_UNREACH:
            return "DEST UNREACHABLE";
        default:
            return "UNKNOWN TYPE";
    };
}

c_str tcpPortToStr(u_short port) {
    c_str result = (c_str)calloc(5 + 1, sizeof(char));
    sprintf(result, "%u", ntohs(port));
    return result;
}

void payloadToAscii(const u_char * payload, u_int size_payload) {
    fprintf(stdout, "Payload %uB\n", size_payload);
    for (int i = 0; i < size_payload; i++) {
        if (isprint(payload[i])) {
            printf("%c ", payload[i]);
        } else {
            printf(". ");
        }

        if ((i % COL_PRE_ROW == 0 && i != 0) || i == (size_payload) - 1) 
            printf("\n");
    }
}
