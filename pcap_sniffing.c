/*
 * <netinet/in.h> contain function to convert bits between NBO(Network Byte Order)
 * and HBO(Host Byte Order). Since x86 is little-endian and NBO is big-endian.
 * So must use it to solve encoding problem
 */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm-generic/socket.h>
/* 
 * pcap itself. You must include it if you want to capture packet.
 */
#include <pcap/dlt.h>
#include <pcap.h>
#include <pcap/pcap.h>
/*
 * standard library
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/wait.h>
/*
 * User defined library
 */
#include "pdu_struct.h"
#include "data_format.h"

/* Global Variables */
const int FAILURE = -1;       // pcap function return -1 when fail
char error[PCAP_ERRBUF_SIZE]; // most pcap function take errbuf as argument. When error ouccr, return info with errbuf

/* Function Definition */
/* Callback processing Ether */
void processEtherFrame(u_char * args, const struct pcap_pkthdr *pkthdr, const u_char * packet);
/* Callback processing IP */
void processIPPacket(u_char * args, u_int caplen, const u_char * packet);
/* Callback processing ARP */
void processARPPacket(u_char * args, u_int caplen, const u_char * packet);
/* Callback processing ICMP */
void processICMPInfo(u_char *args, u_int caplen, const u_char * packet);
/* Callback processing TCP */
void processTCPSegment(u_char * args, u_int caplen, const u_char * packet);
/* Print Devices Info */
void printDevicesInfo(const pcap_if_t *devices);

int main(int argc, char *argv[]) {
    /* config here */
    /* Device config */
    const u_int MAX_BEYT_TO_CAP   = BUFSIZ; // the total bytes a device can capture
    const u_int TIME_OUT_MS       = 1000;   // how much time, by millisecond,  should driver quit core mode to user mode, for data transfer
    const int IS_PROMISC_MODE     = 1;      // whether capture the packet that not sent/received by host
    /* Filter config */
    char *filter_exp              = "";     // the filter to compile, default to capture anything
    const int IS_COMPILE_OPTIMIZE = 0;      // whether optimize the filter been compiled
    /* Capture loop conifg */
    const int PACK_TO_CAP         = 20;     // How much packet to capture

    /* Command line argument */
    if (argc >= 2) {
        fprintf(stdout, "Use filter: %s\n", argv[1]);
        filter_exp = argv[1];
    } else {
        fprintf(stdout, "Use default filter: %s\n", filter_exp);
    }

    /* 1. Fetch devices info and select one */
    pcap_if_t *devices, *temp;
    int i;
    if (pcap_findalldevs(&devices, error) == FAILURE) {
        fprintf(stderr, "Error in pcap findalldevs:\n%s\n", error);
        return -1;
    }
    // printDevicesInfo(devices);
    const char * const dev = devices->name;
    fprintf(stdout, "Choose default devices: %s\n", dev);

    /* 2. Detect the net and mask of device */
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(dev, &net, &mask, error) == FAILURE) {
        fprintf(stderr, "Can't get net, mask for device %s\n%s\n", dev, error);
        net  = 0;
        mask = 0;
    }
    fprintf(stdout, "Device %s:\n" "\tIP:\t%s\n" "\tMask:\t%s\n",
        dev,
        // must add strdup or the string will repeat the first string, such weird
        strdup(inet_ntoa((struct in_addr){ net })),
        strdup(inet_ntoa((struct in_addr){ mask }))
    );

    /* 3. Open device for sniffing
     * pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
     * device  : the name of device to sniffing
     * snaplen : the max number of bytes to captured by pcap
     * promisc : when true, set to promiscuous mode(captured until a error occur)
     * to_ms   : read time out in milliseconds, 0 means no time out
     * ebuf    : store error info of this function
     */
    pcap_t *handle; // the capture session
    handle = pcap_open_live(dev, MAX_BEYT_TO_CAP, IS_PROMISC_MODE, TIME_OUT_MS, error);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\nTry `sudo` maybe?\n", dev, error);
        return -1;
    }
    fprintf(stdout, "Open device %s success!\n", dev);
    
    /* 4. Detect the link-layer header type */
    // LINKTYPE_ETHERNET = 1 = DLT_EN10MB
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Devices %s doesn't provide Ethernet headers - not supported\n", dev);
    }
    fprintf(stdout, "Device %s support Ethernet headers\n", dev);

    /* 5. Complie filter
     * see the grammar of filter in `$man pcap-filter -s 7`
     * int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
     * p        : session handle
     * fp       : reference to the place storing the compiled version of filter
     * str      : filter in regular string format
     * optimize : 1 on, 0 off
     * netmask  : as the name say
     * return   : -1 for failure, others for success
     */
    struct bpf_program fp;
    fprintf(stdout, "Compiling filter %s\n", filter_exp);
    if (pcap_compile(handle, &fp, filter_exp, IS_COMPILE_OPTIMIZE, net) == FAILURE) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    /* 6. Apply filter */
    fprintf(stdout, "Install BFP\n");
    if (pcap_setfilter(handle, &fp) == FAILURE) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    /* 7. Capture packet */
    /* use pcap_loop
     * int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
     * p        : handle
     * cnt      : how many packets should sniffing before returning(negative value means sniff until an error occur)
     * callback : function pointer
     * user     : send the data you want to send for callback
     * pcap_loop return when cnt run of, pcap_dispatch return when processed the first batch of packet sent by system 
     */
   
    /* prototype of callback function:
     * void got_packet(u_char *args, const struct pcap_pkthdr header, const u_char *packet);
     * args   : corresponds to user
     * header : pcap header
     * pcaket : pointer point to the actual packet
     */
    u_int counter = 0;
    fprintf(stdout, "Capturing now:\n");
    pcap_loop(handle, PACK_TO_CAP, processEtherFrame, (u_char *)&counter);
    fprintf(stdout, "Capture %d/%d\n", counter, PACK_TO_CAP);

    /* 7. Close the session */
    pcap_close(handle);
    return 0;
}

void processEtherFrame(u_char * args, const struct pcap_pkthdr *pkthdr, const u_char * packet) {
    u_int *counter = (u_int *)args;
    fprintf(stdout, "Packet: %u\n", ++(*counter));
    fprintf(stdout, "Capture: %d B; Packet: %d B\n", pkthdr->caplen, pkthdr->len);

    const sniff_ethernet_t *ethernet = (sniff_ethernet_t *)(packet);          // the ethernet header
    const u_char *payload            = packet + SIZE_ETHERNET_HEADER;         // packet payload
    const u_int size_payload         = pkthdr->caplen - SIZE_ETHERNET_HEADER; // size of payload

    /* ethernet header */
    fprintf(stdout, "%s -> %s [size: %u B; protocol: %s]\n",
        etherHostToStr(ethernet->ether_shost),
        etherHostToStr(ethernet->ether_dhost),
        SIZE_ETHERNET_HEADER,
        etherType(ethernet->ether_type)    
    );

    /* next layer */
    switch (ntohs(ethernet->ether_type)) {
        case ETHER_TYPE_IP4:
            processIPPacket(NULL, size_payload, payload); return;
        default:
            fprintf(stdout, "\n\n"); return;
    }
}

void processIPPacket(u_char * args, u_int caplen, const u_char * packet) {
    const sniff_ip_t *ip     = (sniff_ip_t *)packet; // the ip header
    const u_int size_ip      = IP_HL(ip) * 4;        // size of ip packet
    const u_char *payload    = packet + size_ip;     // payload
    const u_int size_payload = caplen - size_ip;     // size of payload

    /* size check */
    if (size_ip < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* IP header */
    fprintf(stdout, "%s -> %s [size: %u B; protocol: %s]\n",
        ipv4AddrToStr(ip->ip_src),
        ipv4AddrToStr(ip->ip_dst),
        size_ip,
        ipv4Type(ip->ip_p)
    );

    /* next layer */
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            processTCPSegment(NULL, size_payload, payload); return;
        case IPPROTO_ICMP:
            processICMPInfo(NULL, size_payload, payload); return;
        default:
            fprintf(stdout, "\n\n"); return;
    }
}

void processTCPSegment(u_char * args, u_int caplen, const u_char * packet) {
    const sniff_tcp_t *tcp   = (sniff_tcp_t *)(packet);       // the tcp header
    const u_int size_tcp     = TH_OFF(tcp) * 4;               // size of tcp segment
    const u_char *payload    = packet + size_tcp;             // payload
    const u_int size_payload = caplen  - size_tcp;            // size of payload

    /* size check */
    if (size_tcp < 20) {
        fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    /* TCP header */
    fprintf(stdout, "%s -> %s [size: %u B; SEQ: %u; ACK %u; FLAG: %c%c%c%c%c%c%c%c]\n",
        tcpPortToStr(tcp->th_sport),
        tcpPortToStr(tcp->th_dport),
        size_tcp,
        ntohl(tcp->th_seq),
        ntohl(tcp->th_ack),
        tcp->th_flags & TH_FIN ? 'F' : '.',
        tcp->th_flags & TH_SYN ? 'S' : '.',
        tcp->th_flags & TH_RST ? 'R' : '.',
        tcp->th_flags & TH_PUSH ? 'P' : '.',
        tcp->th_flags & TH_ACK ? 'A' : '.',
        tcp->th_flags & TH_UGR ? 'U' : '.',
        tcp->th_flags & TH_ECE ? 'E' : '.',
        tcp->th_flags & TH_CWR ? 'C' : '.'
    );

    /* payload */
    if (size_payload > 0) payloadToAscii(payload, size_payload);
    fprintf(stdout, "\n\n");
}

void processARPPacket(u_char * args, u_int caplen, const u_char * packet) {
    return;
}

void processICMPInfo(u_char *args, u_int caplen, const u_char * packet) {
    const sniff_icmp_t *icmp = (sniff_icmp_t *)(packet);   // icmp
    const u_char *payload    = packet + SIZE_ICMP_HEADER;  // payload
    const u_int size_payload = caplen  - SIZE_ICMP_HEADER; // size of payload

    /* ICMP header */
    fprintf(stdout, "[type: %s]\n", 
        icmpType(icmp->icmp_type)
    );

    /* payload */
    if (size_payload > 0) payloadToAscii(payload, size_payload);
    fprintf(stdout, "\n\n");
}

void printDevicesInfo(const pcap_if_t *devices) {
    const pcap_if_t *temp;
    int i;
    fprintf(stdout, "Interfaces present on the system are:\n");
    for (temp = devices, i = 0; temp != NULL; temp = temp->next) {
        fprintf(stdout, "%d: %s\n" "\t%s\n",
            ++i, temp->name,
            temp->description != NULL ? temp->description : "No description available"
        );
    }
}
