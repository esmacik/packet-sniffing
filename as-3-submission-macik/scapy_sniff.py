#!/usr/bin/python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

pkt = sniff(prn=print_pkt, filter="icmp")
#pkt = sniff(prn=print_pkt, filter="tcp and src host 8.8.8.8 and dst port 8")