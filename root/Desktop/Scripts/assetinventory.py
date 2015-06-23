import socket
from socket import *

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
if sniffer:
    print "Works"
else:
    pass
sniffer.bind(("192.168.1.98", 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
