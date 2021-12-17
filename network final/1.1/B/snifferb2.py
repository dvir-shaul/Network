#!/usr/bin/env python3
from scapy.all import *

# sniffing tcp packets with port 23(telnet) to host 10.0.2.4
print("sniffing packets")

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter = 'tcp and dst port 23 and src host 10.0.2.4', prn = print_pkt)
