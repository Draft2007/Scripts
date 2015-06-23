## This Script is the Framework of a Network Intrusion Detection System ##

import re
from scapy.all import *

def main():
    conf.iface = "eth0"
    try:
        sniff(prn=checkRules)
        buildPacket(pkt)
    except:
        print "main error"
    
    
if __name__ == "__main__":
    main()
