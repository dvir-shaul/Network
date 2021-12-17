#!/usr/bin/python3
from scapy.all import *

# sniffing icmp packets and spoof the reply even if destinatin non-exsist
print("sniff spoff packets now")

def spoof_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
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

pkt = sniff(iface = ['br-71177225e579','enp0s3'], filter = 'icmp and src host 10.0.2.4', prn = spoof_pkt)


