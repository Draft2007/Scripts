#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import *

# Creates a dictionary of DNS records
dnsRecords = {}


def handlePkt(pkt):
	# .haslayer Takes a protocol type as input and returns a 
	# boolean.  If packet contains DNSRR, we extract the rrname and
	# rdata variables.
	if pkt.haslayer(DNSRR):
		rrname = pkt.getlayer(DNSRR).rrname
		rdata = pkt.getlayer(DNSRR).rdata
        
		# If we have seen Domain Name before, check to see if it had
		# previous IP associated with it
		if dnsRecords.has_key(rrname):
			if rdata not in dnsRecords[rrname]:
				dnsRecords[rrname].append(rdata)
        
		# if the Domain was seen before and has a different IP,
		# we add the name to the first element of the array stored
		# as our dictionary value
		else:
			dnsRecords[rrname] = []
			dnsRecords[rrname].append(rdata)

# To detect fast flux, we need to know which domain names have 
# multiple addresses.  After we examine all packets, we print out the
# domain names and how many unique IP addresses exist for each domain
# name
def main():
	# Uses the scapy rdpcap function to read the pcap file
	pkts = rdpcap('fastFlux.pcap')
	for pkt in pkts:  
		handlePkt(pkt)
    
	for item in dnsRecords:
		print '[+] '+item+' has '+str(len(dnsRecords[item])) \
            + ' unique IPs.'


if __name__ == '__main__':
    main()
