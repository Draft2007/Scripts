#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import *

interface = 'mon0'
probeReqs = []


def sniffProbe(p):
    # Sorts out only packets that have a Dot11ProbeReq
	if p.haslayer(Dot11ProbeReq):
        # Saves the Dot11ProbeReq info as the netName
		netName = p.getlayer(Dot11ProbeReq).info
        # Checks to see if we have already added the netName before
		# appending the name to the array of probeReqs
		if netName not in probeReqs:
            probeReqs.append(netName)
            print '[+] Detected New Probe Request: ' + netName


sniff(iface=interface, prn=sniffProbe)

