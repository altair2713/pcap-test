#Makefile
all: pcap-test

pcap-test: main.o
	g++ -o pcap-test main.o -lpcap

main.o: main.cpp

clean:
	rm -f pcap-test
	rm -f *.o
