## This Script is the Framework of a Network Intrusion Detection System ##

import re
from scapy.all import *

def sniffer(pkt):
    conf.iface = "Wireless LAN adapter Wireless Network Connection:"
    try:
        print pkt
    except:
        print "Fucking error"
        
def main():
    try:
        sniff(prn=sniffer)
        
    except:
        print "main error"
    
    
if __name__ == "__main__":
    main()
