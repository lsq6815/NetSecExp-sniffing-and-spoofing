#ifndef DATA_FORMAT_H
#define DATA_FORMAT_H
#include <sys/types.h>
#include <stdlib.h>
#include "pdu_struct.h"
typedef char * c_str;
/* Convert the raw data of PDU to human readable format */
c_str ether_host_to_str(const u_char *host) {
    c_str result = (c_str)malloc(ETHER_ADDR_LEN);
}
#endif
