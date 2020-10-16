#ifndef DATA_FORMAT_H
#define DATA_FORMAT_H
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include "pdu_struct.h"
typedef char * c_str;
#define COL_PRE_ROW (32)
/* Convert raw ether data of PDU to human readable format */
c_str etherHostToStr(const u_char host[]);
/* Return ether type */
const c_str etherType(u_short ether_type);

/* Convert raw ip data to number-and-dot notation */
c_str ipv4AddrToStr(struct in_addr addr);
/* Return protocol type */
const c_str ipv4Type(u_char protocol);

/* Return ICMP type */
const c_str icmpType(u_char type);

/* Convert raw tcp data to string */
c_str tcpPortToStr(u_short port);
/* Convert payload to ASCII */
void payloadToAscii(const u_char * payload, u_int pd_len);

#endif
