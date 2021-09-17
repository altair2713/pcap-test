#include <pcap.h>
#include <stdbool.h>
#include <cstdio>
#include <libnet.h>
#include <algorithm>
#include <netinet/ether.h>
typedef struct libnet_ethernet_hdr ETH_HDR;
typedef struct libnet_ipv4_hdr IP_HDR;
typedef struct libnet_tcp_hdr TCP_HDR;
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
void print(ETH_HDR* ethernet, IP_HDR* ip, TCP_HDR* tcp)
{
	uint8_t* payload=(uint8_t*)tcp+((uint8_t)tcp->th_off<<2);
	uint16_t data_size=ntohs(ip->ip_len)-((uint16_t)ip->ip_hl<<2)-((uint16_t)tcp->th_off<<2);
	data_size=std::min(data_size,(uint16_t)8);
	printf("Ethernet Header's src mac : %s\n",ether_ntoa((ether_addr*)ethernet->ether_shost));
	printf("Ethernet Header's dst mac : %s\n",ether_ntoa((ether_addr*)ethernet->ether_dhost));
	printf("IP Header's src ip : %s\n",inet_ntoa(ip->ip_src));
	printf("IP Header's dst ip : %s\n",inet_ntoa(ip->ip_dst));
	printf("TCP Header's src port : %u\n",ntohs(tcp->th_sport));
	printf("TCP Header's dst port : %u\n",ntohs(tcp->th_dport));
	printf("Payload's size : %u\n",data_size);
	for(uint16_t i = 0; i < data_size; i++) printf("0x%x ",payload[i]);
	printf("\n\n");
	return;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv)) return -1;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		ETH_HDR* ethernet=(ETH_HDR*)packet;
		if(ntohs(ethernet->ether_type)!=ETHERTYPE_IP) {
			printf("It's not IPv4\n");
			continue;
		}
		IP_HDR* ip=(IP_HDR*)(packet+sizeof(ETH_HDR));
		if(ip->ip_p!=IPPROTO_TCP) {
			printf("It's not TCP\n");
			continue;
		}
		TCP_HDR* tcp=(TCP_HDR*)(packet+sizeof(ETH_HDR)+((uint8_t)ip->ip_hl<<2));
		print(ethernet,ip,tcp);
	}
	pcap_close(pcap);
	return 0;
}
