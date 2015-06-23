#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import optparse
from scapy.all import *
from IPy import IP as IPTEST

ttlValues = {}
THRESH = 5

# Takes a source address with it's respective recieved TTL as
# input and prints out a message for invalid TTLs
def checkTTL(ipsrc, ttl):
    
	# Quick conditional statement to eliminate packets from private
	# addresses (10.0.0.0-10.255.255.255), etc
	if IPTEST(ipsrc).iptype() == 'PRIVATE':
        return
	
	# Checks to see if we have seen the ip address previously
	# in order to avoid adding duplicates
    if not ttlValues.has_key(ipsrc):
        
		# Uses scapy to build an ip packet with dest address
		# equal to the source previous packet
		pkt = sr1(IP(dst=ipsrc) / ICMP(), \
          retry=0, timeout=1, verbose=0)
        # Once the destination responds, Extracts the TTL values
		# and inputs into a dictionary, indexed by IP source 
		# address
		ttlValues[ipsrc] = pkt.ttl

    # Checks to see if difference between actual received TTL 
	# and TTL on original packets exceeds Declared Threshold 
	# Value and prints warning message on screen
	if abs(int(ttl) - int(ttlValues[ipsrc])) > THRESH:
        print '\n[!] Detected Possible Spoofed Packet From: '\
          + ipsrc
        print '[!] TTL: ' + ttl + ', Actual TTL: ' \
            + str(ttlValues[ipsrc])

# Returns the Source IP address and TTL of incoming packets
def testTTL(pkt):
    try:
        if pkt.haslayer(IP):
            ipsrc = pkt.getlayer(IP).src
            ttl = str(pkt.ttl)
            checkTTL(ipsrc, ttl)
    except:

        pass


def main():
    
	# Creates  the option parser
	parser = optparse.OptionParser("usage %prog "+\
      "-i <interface> -t <thresh>")
    parser.add_option('-i', dest='iface', type='string',\
      help='specify network interface')
    parser.add_option('-t', dest='thresh', type='int',
      help='specify threshold count ')
	
	# The user-defined options are passed to the created option
	# parser
    (options, args) = parser.parse_args()
    
	# If the user didn't specify an iface, it will default to eth0
	if options.iface == None:
        conf.iface = 'eth0'
    else:
        conf.iface = options.iface
    
	# If the user didn't specify a Threshold, default is set to 5
	if options.thresh != None:
        THRESH = options.thresh
    else:
        THRESH = 5

    sniff(prn=testTTL, store=0)


if __name__ == '__main__':
    main()
