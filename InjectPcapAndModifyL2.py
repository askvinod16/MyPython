! /usr/bin/env python
from scapy.all import *
import binascii
import pprint
import sys
import os


#intface="lo"
intface="eth01"
#intface="eth2"

ip_count=0
ip_size=0
ip_tcp_count=0
ip_tcp_size=0
ip_udp_count=0
ip_udp_size=0


pcap_file=sys.argv[1]
capture=rdpcap(pcap_file)
for pkt in capture:
        ip_pkt=pkt.getlayer(IP)
        t=pkt.getlayer(TCP)
        u=pkt.getlayer(UDP)
        eth=Ether(dst="00:50:56:8d:1e:b0",src="00:50:56:8d:e7:fe")
        p=eth/ip_pkt
        sendp(p, iface=intface,verbose=True)
        ip_count=ip_count+1
        ip_size=ip_size+len(ip_pkt)
        if(t):
                ip_tcp_count=ip_tcp_count+1
                ip_tcp_size=ip_tcp_size+len(t.payload)
        if(u):
                ip_udp_count=ip_udp_count+1
                ip_udp_size=ip_udp_size+len(u)

print("IP,SIZE,TCP,TCP_SiZE,UDP,UDP_SIZE")
print(ip_count,ip_size,ip_tcp_count,ip_tcp_size,ip_udp_count,ip_udp_size)
