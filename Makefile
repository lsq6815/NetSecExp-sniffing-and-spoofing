TARGET:=sniffing.out
HEADERS:=data_format.h pdu_struct.h
OBJS:=pcap_sniffing.o data_format.o

edit: $(OBJS)
	gcc $(OBJS) -lpcap -o $(TARGET)
pcap_sniffing.o: pcap_sniffing.c $(HEADERS)
	gcc -o pcap_sniffing.o -c pcap_sniffing.c
data_format.o: data_format.c $(HEADERS)
	gcc -o data_format.o -c data_format.c
clean:
	rm *.o *.out .*.swp
