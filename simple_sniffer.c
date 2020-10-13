#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#define MAX_BYTE_TO_CAP 2048

/* Callback function to process packet captured */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
    int i        = 0;
    int *counter = (int *)arg;

    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload: \n");
    for (int i = 0; i < (pkthdr->len); i++) {
        if (isprint(packet[i])) {
            printf("%c ", packet[i]);
        } else {
            printf(". ");
        }

        if ((i % 16 == 0 && i != 0) || i == (pkthdr->len) - 1) 
            printf("\n");
    }
    return;
}


int main(int argc, char *argv[]) {
    int i = 0, count = 0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    pcap_if_t *devices;
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        puts(errbuf);
        return -1;
    }
    device = devices->name;
    descr = pcap_open_live(device, MAX_BYTE_TO_CAP, 1, 512, errbuf);
    pcap_loop(descr, 10, processPacket, (u_char *)&count);
}




















