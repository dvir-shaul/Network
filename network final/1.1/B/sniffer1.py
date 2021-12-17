#!/usr/bin/env python3
from scapy.all import *

# sniffing icmp packets
print("sniffing packets")

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)
