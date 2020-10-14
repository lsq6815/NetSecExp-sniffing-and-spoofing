#include "data_format.h"
#include "pdu_struct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

c_str etherHostToStr(const u_char *host) {
    // use char array, no need for NBO convert
    c_str result = (c_str)calloc(ETHER_ADDR_LEN * 2 + 5 + 1, sizeof(char));
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", 
            host[0],host[1],host[2],host[3],host[4],host[5]
    );
    return result;
}

const char *etherType(u_short ether_type) {
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

const char *ipv4Type(u_char protocol) {
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


c_str tcpPortToStr(u_short port) {
    c_str result = (c_str)calloc(5 + 1, sizeof(char));
    sprintf(result, "%u", ntohs(port));
    return result;
}

c_str payloadToAscii(const u_char * payload, u_int pd_len) {
   int round = pd_len / COL_PRE_ROW;
   int ret   = pd_len % COL_PRE_ROW;
   int index = 0;
   c_str result = (c_str)calloc(pd_len + round + 1, sizeof(char)); // round stands for \n
   for (int i = 0; i < round; i++) {
      for (int j = 0; j < COL_PRE_ROW; j++) {
          result[index++] = payload[i * COL_PRE_ROW + j];
      }
      result[index++] = '\n';
   }
   return result;
}
