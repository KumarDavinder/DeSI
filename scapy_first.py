#! /usr/bin/env python
import sys
from scapy.all import send,IP,ICMP,TCP,Ether
p = IP(dst="2.0.0.1", src="1.0.0.2")/TCP(sport=21, dport=80)/"Create pkt"
if p:
 #p.show()
 send(p)
 
