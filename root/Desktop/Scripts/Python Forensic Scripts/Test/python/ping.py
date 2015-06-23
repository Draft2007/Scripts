import socket
import os
import sys
from scapy.all import *
import _ping


conftgts = []

def ping(network):
    tgts = []
    
    for ip in range(1,15):
        tgts.append(network + '.' + str(ip))
   #     print "Addresses added to List..."
    for tgt in tgts:
        echopacket = IP(dst=tgt)/ICMP()
        response = sr1(echopacket, timeout=1)
        if response != None:
            conftgts.append(tgt)
        else:
            pass
    for conftgt in conftgts:
        print "Confirmed Target: "+ conftgt
    return conftgts

def portscan(conftgt):
    closedports = []
    openports = []
    filteredports = []
    
    print "Starting Port Scan on: " + conftgt
    for port in range(21,30):
        packet = IP(dst=conftgt)/TCP(dport=int(port), flags="S", seq=40)
        
        result = sr1(packet, timeout=1)
        
        if not result:
            closedports.append(port)
        else:
            openports.append(port)
            
    for openport in openports:
        print conftgt + '\t' + str(openport)
        
    
    


def main():
    
    network= "10.99.1"
    
    ping(network)
    
    for conftgt in conftgts:
        portscan(conftgt)


if __name__ == "__main__":
    main()