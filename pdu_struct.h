#ifndef TCP_FRAME_STRUCT_H
#define TCP_FRAME_STRUCT_H
#include <netinet/in.h>
#include <pcap.h>
#include <sys/types.h>
#define ETHER_ADDR_LEN 6
/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address : 6B
    u_char ether_shost[ETHER_ADDR_LEN]; // Source host address      : 6B
    u_short ether_type;                 // IP? ARP? RARP? etc       : 2B
};

/* IP header */
struct sniff_ip {
        u_char ip_vhl;                 // version << 4 | header length >> 2 : 1B
        u_char ip_tos;                 // type of service                   : 1B
        u_short ip_len;                // total length                      : 2B
        u_short ip_id;                 // identification                    : 2B
        u_short ip_off;                // fragment offset field             : 2B
#define IP_RF 0x8000;                  // reserved fragment flag
#define IP_DF 0x4000;                  // dont fragment flag
#define IP_MF 0x2000;                  // more for fragment flag
#define IP_OFFMASK 0x1fff;             // mak for fragment bits
        u_char ip_ttl;                 // time to live                      : 1B
        u_char ip_p;                   // protocol                          : 1B
        u_short ip_usm;                // checksum                          : 2B
        struct in_addr ip_src, ip_dst; // source and dest address           : 4B : 4B
};
#define IP_HL(ip)  ( ( (ip)->ip_vhl) & 0x0f )
#define IP_V(ip)   ( ( (ip)->ip_vhl) >> 4 )

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport; // source port            : 2B
        u_short th_dport; // destination port       : 2B
        tcp_seq th_seq;   // sequence number        : 4B
        tcp_seq th_ack;   // acknowledgement number : 4B
        u_char th_offx2;  // data offset, rsvd      : 1B
#define TH_OFF(th) ( ( (th)->th_offx2 & 0xf0 ) >> 4 )
        u_char th_flags;  //                        : 1B
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_UGR  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;   // window                 : 2B
        u_short th_sum;   // check sum              : 2B
        u_short urp;      // urgent pointer         : 2B
};
#endif
