#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
from scapy.all import *

interface = 'mon0'
# Instantiate Arrays for HiddenNets and Unhidden Nets so the 
# source address can be compared
hiddenNets = []
unhiddenNets = []

def sniffDot11(p):
    
	# Hidden SSIDs are sent in Dot11ProbeResp packets
    if p.haslayer(Dot11ProbeResp):
        addr2 = p.getlayer(Dot11).addr2
        # Checks to see if the source address is a hidden network
		# If the address hasn't been added yet or is an unhidden
		# network, it sends to loop to the Dot11Beacon loop
		if (addr2 in hiddenNets) & (addr2 not in unhiddenNets):
            netName = p.getlayer(Dot11ProbeResp).info
            print '[+] Decloaked Hidden SSID : ' +\
                netName + ' for MAC: ' + addr2
            unhiddenNets.append(addr2)
    
    # Checks if packet has a Dot11Beacon
	if p.haslayer(Dot11Beacon):
        # Filters out packets that have a blank info field (Hidden
		# SSID)
		if p.getlayer(Dot11Beacon).info == '':
            # Extracts the source address of the packet
			addr2 = p.getlayer(Dot11).addr2
            # If address is not yet in hiddenNets array, we print and
			# add the addr2 to the hiddenNets array
			if addr2 not in hiddenNets:
                print '[-] Detected Hidden SSID: ' +\
                    'with MAC:' + addr2
                hiddenNets.append(addr2)


sniff(iface=interface, prn=sniffDot11)

