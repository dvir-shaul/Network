#!/usr/bin/env python3
from scapy.all import *

# sniffing packets with spesific subnet
print("sniffing packets")

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='dst net 104.17.96.0/24',prn=print_pkt)
