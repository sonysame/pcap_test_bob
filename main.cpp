#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

struct ethernet{
	uint8_t destination_address[ETHER_ADDR_LEN];
	uint8_t source_address[ETHER_ADDR_LEN];
	uint16_t ethernet_type;
};
struct ip{
	uint8_t ip_hl:4, ip_v:4;
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	uint32_t ip_src;
	uint32_t ip_dst;
};
struct tcp{
	uint16_t tcp_sport;
	uint16_t tcp_dport;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
	uint8_t tcp_x2:4, tcp_off:4;
	uint8_t tcp_flags;
	uint16_t tcp_win;
	uint16_t tcp_sum;
	uint16_t tcp_urp;
};

void print_mac(char * str,uint8_t * addr){
	int i;
	printf("%s: ",str);
	for(i=0;i<ETHER_ADDR_LEN-1;i++)printf("%02x:",(u_char)*(addr+i));
	printf("%02x\n",(u_char)*(addr+i));
}
void print_ip(char * str, uint32_t ip){
	int i;
	printf("%s: ",str);
	for(i=sizeof(ip)-1;i>0;i--)printf("%d.",(ip>>(i*8))&0xff);
	printf("%d\n",ip&0xff);
}
void print_port(char * str, uint16_t port){
	printf("%s: %d\n",str,port);
}
void print_data(char * data_addr, unsigned int len=10){
	int i;
	if(len)printf("\nData:\n");
	for(i=0;i<len;i++){
		printf("%02x ",(u_char)*(data_addr+i));
		if((i&0xf)==0xf)printf("\n");
	}
}
void dump(u_char * p, int len){
	for(int i=0;i<len;i++){
		printf("%02x ",*p);
		p++;
		if((i&0x0f)==0x0f)
			printf("\n");
	}
}



void dump2(char * p, int len){
	int i;
	struct ethernet * a_ptr=(struct ethernet *)p;
	print_mac("dst mac",a_ptr->destination_address);
	print_mac("src mac",a_ptr->source_address);
	if(ntohs(a_ptr->ethernet_type)==ETHERTYPE_IP){
		printf("\nipv4\n");
		struct ip * a_ptr=(struct ip *)(p+sizeof(struct ethernet));
		print_ip("dst ip",ntohl(a_ptr->ip_dst));
		print_ip("src ip",ntohl(a_ptr->ip_src));
		unsigned int ip_hlen=(a_ptr->ip_hl)*4;
		unsigned int ip_tlen=a_ptr->ip_len;
		if((a_ptr->ip_p)==IPPROTO_TCP){
			printf("\nTCP\n");
			struct tcp * a_ptr=(struct tcp *)(p+sizeof(struct ethernet)+ip_hlen);
			print_port("src port", ntohs(a_ptr->tcp_sport));
			print_port("dst port",ntohs(a_ptr->tcp_dport));
			unsigned int tcp_hlen=(a_ptr->tcp_off)*4;
			unsigned int data_len=(ntohs(ip_tlen)-(ip_hlen+tcp_hlen));
			data_len>10?print_data(p+sizeof(struct ethernet)+ip_hlen+tcp_hlen):print_data(p+sizeof(struct ethernet)+ip_hlen+tcp_hlen,data_len);
		}
	}
	printf("\n=========================================================\n");
}


void usage() {
  printf("syntax : pcap_test <interface>\n");
  printf("example : pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
 // pcap_t* handle=pcap_open_offline("./tcp-port-80-test.gilgil.pcap",errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
 
  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n%u bytes captured\n", header->caplen);
	dump((u_char *)packet, header->caplen);
	printf("\n\n");
	dump2((char *)packet, header->caplen);
	printf("\n");
  }

  pcap_close(handle);
  return 0;
}
