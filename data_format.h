#ifndef DATA_FORMAT_H
#define DATA_FORMAT_H
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include "pdu_struct.h"
typedef char * c_str;
c_str byte_to_bin_str(u_char byte);
c_str byte_to_hex_str(u_char byte);
/* Convert the raw data of PDU to human readable format */
c_str ether_host_to_str(const u_char *host);

c_str ip_addr_to_str(bpf_u_int32 addr);
#endif
