#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "myheaders.h"
  
  
#define PACKET_len 256
#define source_ip "10.0.2.6"
#define destination_ip "1.2.3.4"
  
unsigned short in_cksum(unsigned short *buf, int len);
void send_raw_ip_packet(struct sniff_ip* ip);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	 struct sniff_ethernet *eth = (struct sniff_ethernet *)packet;
	 if(ntohs(eth->ether_type) == 0x800)
	 {
	 	struct sniff_ip *ip1 = (struct sniff_ip *)(packet + sizeof(struct sniff_ethernet));	 
	 	char buff[PACKET_len];
		memset(buff, 0, PACKET_len);
	 	struct sniff_icmp *icmp1 = (struct sniff_icmp *)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
		if(icmp1->icmp_type == 8)
		{
			
			printf("Got a packet\n"); 	
	 		printf("Protocol: icmp\n");
                	printf("From: %s\n", inet_ntoa(ip1->ip_src));
                	printf("to: %s\n", inet_ntoa(ip1->ip_dst));
                	char buff[PACKET_len];
	
			memset(buff, 0, PACKET_len);
	
			struct sniff_icmp *icmp = (struct sniff_icmp *)(buff + sizeof(struct sniff_ip));
			icmp->icmp_type = 0;
			icmp->icmp_cksum = in_cksum((unsigned short *)icmp, sizeof(struct sniff_icmp));
	
			struct sniff_ip *ip = (struct sniff_ip *)buff;
			ip->ip_hl = 5;
			ip->ip_v = 4;
			ip->ip_tos = 16;
			ip->ip_id = htons(54321);
			ip->ip_ttl = 64;
			ip->ip_src.s_addr = ip1->ip_dst.s_addr;
			ip->ip_dst.s_addr = ip1->ip_src.s_addr;
			ip->ip_p = IPPROTO_ICMP;
			ip->ip_len = htons(sizeof(struct sniff_ip) + sizeof(struct sniff_icmp));
	
                	send_raw_ip_packet(ip);
                }
	 }
	
}

int main() { 
	pcap_t *handle;
 	char errbuf[PCAP_ERRBUF_SIZE]; 
 	struct bpf_program fp; 
 	char filter_exp[] = "ip proto ICMP and host 10.0.2.6"; 
 	bpf_u_int32 net;
 	// Step 1: Open live pcap session on NIC with name enp0s3 // Students needs to change "eth3" to the 		name 
 	//found on their own machines (using ifconfig).
 	
 	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
 	if(handle == NULL)
 	{
 		printf("couldn't open device enp0s3: %s\n",errbuf);
 		return 0;
 	}
 	// Step 2: Compile filter_exp into BPF psuedo-code 
 	if(pcap_compile(handle, &fp, filter_exp, 0, net == -1))
 	{
 		printf("couldn't parse filter %s: %s\n",filter_exp,pcap_geterr(handle));
 		return 1;
 	}
 	if(pcap_setfilter(handle, &fp) == -1)
 	{
 		printf("couldn't install filter %s: %s\n",filter_exp,pcap_geterr(handle));
 		return 2;
 	}
 	 
 	// Step 3: Capture packets 
 	pcap_loop(handle, -1, got_packet, NULL); 
 	pcap_close(handle); //Close the handle 
 	return 0; 
 }

void send_raw_ip_packet(struct sniff_ip* ip)
{
	struct sockaddr_in dest_data;
	int ena = 1;

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock < 0)
		return;
	
	setsockopt(sock,IPPROTO_IP,IP_HDRINCL, &ena, sizeof(ena));
	
	dest_data.sin_family = AF_INET;
	dest_data.sin_addr = ip->ip_dst;
	
	printf("sending a spoofed ip packet   \n");
	if(sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_data, sizeof(dest_data)) < 0)
	{
		printf("couldn't send the packet\n");
		return;
	}
	else
	{
		printf("From: %s\n", inet_ntoa(ip->ip_src));
                printf("to: %s\n", inet_ntoa(ip->ip_dst));
	}
	close(sock);	
}
unsigned short in_cksum(unsigned short *buf, int len)
{
	unsigned short *w = buf;
	int nleft = len;
	int sum = 0;
	unsigned short temp = 0;
	
	while (nleft > 1){
		sum+= *w++;
		nleft -= 2;
	}
	
	if(nleft == 1)
	{
		*(u_char *)(&temp) = *(u_char *)w;
		sum += temp;
	}
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >>16);
	return (unsigned short)(~sum);
}



