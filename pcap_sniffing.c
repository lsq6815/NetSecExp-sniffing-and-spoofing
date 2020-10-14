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
/*
 * User defined library
 */
#include "pdu_struct.h"
#include "data_format.h"

/* Global Variables */
const int FAILURE = -1;       // pcap function return -1 when fail
char error[PCAP_ERRBUF_SIZE]; // most pcap function take errbuf as argument. When error ouccr, return info with errbuf

/* Function Definition */
/* function for pcap_loop callback */
void processPacket(u_char * args, const struct pcap_pkthdr *pkthdr, const u_char * packet);
/* Print Devices Info */
void printDevicesInfo(const pcap_if_t *devices);

int main(int argc, char *argv[]) {
    /* config here */
    /* Device config */
    const u_int MAX_BEYT_TO_CAP   = BUFSIZ; // the total bytes a device can capture
    const u_int TIME_OUT_MS       = 1000;   // how much time, by millisecond,  should driver quit core mode to user mode, for data transfer
    const int IS_PROMISC_MODE     = 1;      // whether capture the packet that not sent/received by host
    /* Filter config */
    const char *filter_exp        = "tcp"; // the filter to compile
    const int IS_COMPILE_OPTIMIZE = 0;     // whether optimize the filter been compiled
    /* Capture loop conifg */
    const int PACK_TO_CAP         = 20;    // How much packet to capture


    /* 1. Fetch devices info and select one */
    pcap_if_t *devices, *temp;
    int i;
    if (pcap_findalldevs(&devices, error) == FAILURE) {
        fprintf(stderr, "Error in pcap findalldevs:\n%s\n", error);
        return -1;
    }
    printDevicesInfo(devices);
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

    /* 5. Complier filter
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
    pcap_loop(handle, PACK_TO_CAP, processPacket, (u_char *)&counter);

    /* 7. Close the session */
    pcap_close(handle);
    return 0;
}

void processPacket(u_char * args, const struct pcap_pkthdr *pkthdr, const u_char * packet) {
    u_int *counter = (u_int *)args;
    fprintf(stdout, "Packet: %u\n", ++(*counter));
    fprintf(stdout, "Capture %d B Packet %d B\n", pkthdr->caplen, pkthdr->len);

    const u_int SIZE_ETHERNET = 14; // ethernet's frame size is always exactly 14B
    u_int size_ip;                // size of ip packet
    u_int size_tcp;               // size of tcp segment
    u_int size_payload;           // size of payload

    const struct sniff_ethernet *ethernet; // the ethernet header
    const struct sniff_ip *ip;             // the ip header
    const struct sniff_tcp *tcp;           // the tcp header
    const u_char *payload;                 // packet payload
    /* magical typecasting */
    /* ethernet header */
    ethernet = (struct sniff_ethernet *)(packet);
    fprintf(stdout, "%s -> %s [size %u B; protocol: %s]\n",
        etherHostToStr(ethernet->ether_shost),
        etherHostToStr(ethernet->ether_dhost),
        SIZE_ETHERNET,
        etherType(ethernet->ether_type)    
    );

    /* ip header */
    ip      = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    fprintf(stdout, "%s -> %s [size: %u B; protocol: %s]\n",
        ipv4AddrToStr(ip->ip_src),
        ipv4AddrToStr(ip->ip_dst),
        size_ip,
        ipv4Type(ip->ip_p)
    );

    /* tcp header */
    tcp      = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    fprintf(stdout, "%s -> %s [%u B]\n",
        tcpPortToStr(tcp->th_sport),
        tcpPortToStr(tcp->th_dport),
        size_tcp
    );

    /* payload */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = pkthdr->caplen - SIZE_ETHERNET - size_ip - size_tcp;
    if (size_payload > 0) {
        fprintf(stdout, "Payload %uB\n", size_payload);
        for (int i = 0; i < (pkthdr->len); i++) {
            if (isprint(packet[i])) {
                printf("%c ", packet[i]);
            } else {
                printf(". ");
            }
    
            if ((i % 32 == 0 && i != 0) || i == (pkthdr->len) - 1) 
                printf("\n");
        }
    }
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

