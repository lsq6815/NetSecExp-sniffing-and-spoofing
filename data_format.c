#include "data_format.h"
#include "pdu_struct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
/* those function is to convert bits into c-style string for further use*/
c_str byte_to_bin_str(u_char byte) {
    c_str result = (c_str)malloc(8);
    sprintf(result, "%c%c%c%c%c%c%c%c", 
        (byte & 0x80 ? '1' : '0'), 
        (byte & 0x40 ? '1' : '0'), 
        (byte & 0x20 ? '1' : '0'), 
        (byte & 0x10 ? '1' : '0'), 
        (byte & 0x08 ? '1' : '0'), 
        (byte & 0x04 ? '1' : '0'), 
        (byte & 0x02 ? '1' : '0'), 
        (byte & 0x01 ? '1' : '0')  
    );
    return result;
}

c_str byte_to_hex_str(u_char byte) {
    c_str result = (c_str)malloc(2);
    const char *hexstr = "0123456789ABCDEF";
    result[0] = hexstr[byte >> 4];
    result[1] = hexstr[byte & 0x0f];
    return result;
}

c_str ether_host_to_str(const u_char *host) {
    c_str result = (c_str)malloc(ETHER_ADDR_LEN * 2 + ETHER_ADDR_LEN - 1);
    sprintf(result, "%02x %02x %02x %02x %02x %02x",
        host[0], host[1], host[2], host[3], host[4], host[5] 
    );
    return "To Be Continuing";
}

c_str ip_addr_to_str(bpf_u_int32 addr) {
    // Don't forget \0
    c_str result = (c_str)malloc(16);
    sprintf(result, "%d.%d.%d.%d", 
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8)  & 0xff,
        (addr >> 0)  & 0xff
    );
    result[15] = '\0';
    return result;
}
