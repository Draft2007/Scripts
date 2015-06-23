# This script is designed to print the raw load contained in 
# each packet

from scapy.all import *


PORT = 5556
def printPkt(pkt):
    if pkt.haslayer(UDP) and pkt.getlayer(UDP).dport == PORT:
        raw = pkt.sprintf('%Raw.load%')
        print raw
conf.iface = 'eth0'
sniff(prn=printPkt)
        