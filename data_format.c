#include "data_format.h"
#include "pdu_struct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

c_str ether_host_to_str(const u_char *host) {
    // use char array, no need for NBO convert
    c_str result = (c_str)malloc(ETHER_ADDR_LEN * 2 + 5);
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", 
            host[0],host[1],host[2],host[3],host[4],host[5]
    );
    return result;
}

c_str ip_addr_to_str(struct in_addr addr) {
    return strdup(inet_ntoa(addr));
}

c_str tcp_port_to_str(u_short port) {
    c_str result = (c_str)malloc(pow(2, 16));
    sprintf(result, "%u", ntohs(port));
    return result;
}
