#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "myheaders.h"
  
#define PACKET_len 256
#define source_ip "16.217.10.4"
#define destination_ip "10.0.2.4"
  
unsigned short in_cksum(unsigned short *buf, int len);
void send_raw_ip_packet(struct sniff_ip* ip);


//this program sends a ping request with a fake ip source 

int main() { 

	char buff[PACKET_len];
	
	memset(buff, 0, PACKET_len);
	
	struct sniff_icmp *icmp = (struct sniff_icmp *)(buff + sizeof(struct sniff_ip));
	icmp->icmp_type = 8;
	icmp->icmp_cksum = in_cksum((unsigned short *)icmp, sizeof(struct sniff_icmp));
	
	struct sniff_ip *ip = (struct sniff_ip *)buff;
	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_tos = 16;
	ip->ip_id = htons(54321);
	ip->ip_ttl = 64;
	ip->ip_src.s_addr = inet_addr(source_ip);
	ip->ip_dst.s_addr = inet_addr(destination_ip);
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_len = htons(sizeof(struct sniff_ip) + sizeof(struct sniff_icmp));
	
	send_raw_ip_packet(ip);
	
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

