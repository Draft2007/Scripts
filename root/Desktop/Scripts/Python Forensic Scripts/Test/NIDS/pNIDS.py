## This Script is the Framework of a Network Intrusion Detection System ##
import checkRules
import buildPacket
import re
from scapy.all import *

def main():
    print 'Starting...'
    conf.iface = "eth0"
    
    try:
        print "Starting..."
	sniff(prn=checkRules)
        buildPacket(pkt)
    except:
        print "main error"
    
    
if __name__ == "__main__":
    main()
