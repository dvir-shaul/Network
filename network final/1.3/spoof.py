from scapy.all import *
a = IP()
a.dst = '8.8.8.8'
a.ttl = 15
b=ICMP()
send(a/b)
