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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
/*
 * User defined library
 */
#include "pdu_struct.h"
#include "data_format.h"

/* Global Variables */
const int FAILURE = -1;       // pcap function return -1 when fail
char error[PCAP_ERRBUF_SIZE]; // most pcap function take errbuf as argument. When error ouccr, return info with errbuf

int main(int argc, char *argv[]) {

    /* 1. Fetch devices info */
    pcap_if_t *devices, *temp;
    if (pcap_findalldevs(&devices, error) == FAILURE) {
        fprintf(stderr, "Error in pcap findalldevs:\n%s\n", error);
        return -1;
    }
    printf("Interfaces present on the system are:\n");
    int i;
    for (temp = devices, i = 0; temp != NULL; temp = temp->next) {
        fprintf(stdout, "%d: %s\n\t%s\n", ++i, temp->name, 
            temp->description != NULL ? temp->description : "No description available"
        );
    }
    const char * const dev = devices->name;
    fprintf(stdout, "Choose default devices: %s\n", dev);

    /* 2. Detect the net and mask of device */
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(dev, &net, &mask, error) == FAILURE) {
       fprintf(stderr, "Can't get net, mask for device %s\n", dev);
       net  = 0;
       mask = 0;
    }
    fprintf(stdout, "Device %s:\n" "\tIP:\t%s\n" "\tMask:\t%s\n",
            dev,
            // must add strdup or the string will repeat the first string, such weird
            strdup(inet_ntoa((struct in_addr){ net })),
            strdup(inet_ntoa((struct in_addr){ mask }))
    );

    /* 3. Open device for sniffing */
    // pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
    // device  : the name of device to sniffing
    // snaplen : the max number of bytes to captured by pcap
    // promisc : when true, set to promiscuous mode(captured until a error occur)
    // to_ms   : read time out in milliseconds, 0 means no time out
    // ebuf    : store error info of this function
    pcap_t *handle; // the capture session
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error);
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

    /* 5. Complier filter */
    // see the grammar of filter in `man pcap-filter -s 7`
    // int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
    // p        : session handle
    // fp       : reference to the place storing the compiled version of filter
    // str      : filter in regular string format
    // optimize : 1 on, 0 off
    // netmask  : as the name say
    // return   : -1 for failure, others for success
    struct bpf_program fp;
    char filter_exp[] = "tcp and port https";
    fprintf(stdout, "Compiling filter %s\n", filter_exp);
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == FAILURE) {
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
    struct pcap_pkthdr header; // the header that pcap give
    const u_char *packet;      // the pcaket in real
    packet = pcap_next(handle, &header);

    /* print its length */
    fprintf(stdout, "Jacked a packet with length of [%d], Captured length of [%d]\n", header.len, header.caplen);
    
    /* use pcap_loop */
    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
    // p        : handle
    // cnt      : how many packets should sniffing before returning(negative value means sniff until an error occur)
    // callback : function pointer
    // user     : send the data you want to send for callback
    //
    // pcap_loop return when cnt run of, pcap_dispatch return when processed the first batch of packet sent by system 
    //
    // prototype of callback function:
    // void got_packet(u_char *args, const struct pcap_pkthdr header, const u_char *packet);
    // args   : corresponds to user
    // header : pcap header
    // pcaket : pointer point to the actual packet
    const int SIZE_ETHERNET = 14; // ethernet's frame size is always exactly 14B
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
    fprintf(stdout, "HOST src: %s\n", ether_host_to_str(ethernet->ether_shost));
    fprintf(stdout, "HOST dst: %s\n", ether_host_to_str(ethernet->ether_dhost));
    fprintf(stdout, "Ethernet Header is fixed to 14B\n");

    /* ip header */
    ip      = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        return -1;
    }
    fprintf(stdout, "IP src: %s\n", ip_addr_to_str(ip->ip_src));
    fprintf(stdout, "IP dst: %s\n", ip_addr_to_str(ip->ip_dst));
    fprintf(stdout, "IP Header size: %u\n", size_ip);
    /* tcp header */
    tcp      = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
    }
    fprintf(stdout, "PORT src: %s\n", tcp_port_to_str(tcp->th_sport));
    fprintf(stdout, "PORT dst: %s\n", tcp_port_to_str(tcp->th_dport));
    fprintf(stdout, "TCP Header size: %u\n", size_tcp);
    /* payload */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = header.caplen - 14 - size_ip - size_tcp;
    fprintf(stdout, "Payload size: %u\n", size_payload);
    if (size_payload > 0) {
        fprintf(stdout, "Content:\n%s\n", payload_to_ascii(payload, size_payload));
    }
    /* 7. Close the session */
    pcap_close(handle);
    return 0;
}
