import socket
import os
import sys
from scapy.all import *

def ping(tgt):
    try:
        packet = IP(dst=tgt)/ICMP(type=8, code=0)
        result = sr1(packet)
        
    except:
        print "Ping Error!"
        exit(1)
        
    return result

def main():
    tgt= "192.168.0.1"
    try:
        ping()
        print result.getlayer(IP)
    except:
        print "Target Error!"

if __name__ == "__main__":
    main()