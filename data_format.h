#ifndef DATA_FORMAT_H
#define DATA_FORMAT_H
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include "pdu_struct.h"
typedef char * c_str;
#define COL_PRE_ROW (16)
/* Convert raw ether data of PDU to human readable format */
c_str etherHostToStr(const u_char host[]);
/* Return ether type */
const char *etherType(u_short ether_type);

/* Convert raw ip data to number-and-dot notation */
c_str ipv4AddrToStr(struct in_addr addr);
/* Return protocol type */
const char *ipv4Type(u_int protocol);

/* Convert raw tcp data to string */
c_str tcpPortToStr(u_short port);
/* Convert payload to ASCII */
c_str payloadToAscii(const u_char * payload, u_int pd_len);
#endif
