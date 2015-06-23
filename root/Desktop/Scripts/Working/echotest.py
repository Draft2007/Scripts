from scapy.all import *


def ping():
    packet = IP(src="192.168.0.1")/ICMP()
    echo = sr1(packet, timeout=1)
    
     