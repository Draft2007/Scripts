#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import *

# Domain Flux is used in attacks like Conficker, in which the
# worm generates bogus DNS names in an attempt to mask the actual
# Command and Control Center.  Most DNS servers lack the ability to
# translate the domain names to actual addresses and instead generate
# error messages

# Reads a network capture and enumerates through all the packets in 
# the capture.
def dnsQRTest(pkt):
    # Looks at the packet layers and makes sure to only test packets
	# originating from source port 53 that contain resource records
	if pkt.haslayer(DNSRR) and pkt.getlayer(UDP).sport == 53:
        rcode = pkt.getlayer(DNS).rcode
        qname = pkt.getlayer(DNSQR).qname
        # When rcode = 3, the domain name does not exist
		if rcode == 3:
            print '[!] Name request lookup failed: ' + qname
            return True
        else:
            return False


def main():
    # Initiates the unAnsReqs variable
	unAnsReqs = 0
    # Reads a network capture and creates a variable pkts with the 
	# returned value
	pkts = rdpcap('domainFlux.pcap')
    for pkt in pkts:
        if dnsQRTest(pkt):
            unAnsReqs = unAnsReqs + 1
    print '[!] '+str(unAnsReqs)+' Total Unanswered Name Requests'


if __name__ == '__main__':
    main()
