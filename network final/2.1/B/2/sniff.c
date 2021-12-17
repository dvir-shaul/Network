  #include <pcap.h>
  #include <stdio.h>
  #include <arpa/inet.h>
 #include "myheaders.h"
  
  // this program sniffs packets from a destination port number in range from 10-100
  
/* This function will be invoked by pcap for each captured packet. We can process each packet inside the function. */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	 printf("Got a packet\n"); 
	 struct sniff_ethernet *eth = (struct sniff_ethernet *)packet;
	 if(ntohs(eth->ether_type) == 0x800)
	 {
	 	struct sniff_ip *ip = (struct sniff_ip *)(packet + sizeof(struct sniff_ethernet));	 	
	 	printf("Protocol: icmp\n");
                printf("From: %s\n", inet_ntoa(ip->ip_src));
                printf("to: %s\n", inet_ntoa(ip->ip_dst));
                
                struct sniff_tcp *tcp = (struct sniff_tcp *)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
                printf("source: %d\n", ntohs(tcp->th_sport));
                printf("destination: %d\n", ntohs(tcp->th_dport));                      
	 }
}

int main() { 
	pcap_t *handle;
 	char errbuf[PCAP_ERRBUF_SIZE]; 
 	struct bpf_program fp; 
 	char filter_exp[] = "proto TCP and dst portrange 10-100"; 
 	bpf_u_int32 net;
 	// Step 1: Open live pcap session on NIC with name eth3 // Students needs to change "eth3" to the 		name 
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
 	// gcc -o sniff sniff.c -lpcap  


