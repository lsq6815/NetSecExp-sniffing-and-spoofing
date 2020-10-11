edit: pcap_sniffing.o data_format.o
	gcc pcap_sniffing.o data_format.o -lpcap -o sniffing.out 
pcap_sniffing.o: pcap_sniffing.c data_format.h pdu_struct.h
	gcc -o pcap_sniffing.o -c pcap_sniffing.c
data_format.o: data_format.c data_format.h pdu_struct.h
	gcc -o data_format.o -c data_format.c
clean:
	rm *.o sniffing.out .*.swp
