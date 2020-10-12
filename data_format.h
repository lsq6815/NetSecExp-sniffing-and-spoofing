#ifndef DATA_FORMAT_H
#define DATA_FORMAT_H
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include "pdu_struct.h"
typedef char * c_str;
#define COL_PRE_ROW (16)
/* Convert raw ether data of PDU to human readable format */
c_str ether_host_to_str(const u_char host[]);
/* Convert raw ip data to number-and-dot notation */
c_str ip_addr_to_str(struct in_addr addr);
/* Convert raw tcp data to string */
c_str tcp_port_to_str(u_short port);
/* Convert payload to ASCII */
c_str payload_to_ascii(const u_char * payload, u_int pd_len);
#endif
