#!/usr/bin/python
# -*- coding: utf-8 -*-

from bluetooth import *


def rfcommCon(addr, port):
    # In order to connect to RFCOMM port, we create a RFCOMM-type
	# BluetoothSocket
	sock = BluetoothSocket(RFCOMM)
    try:
        # Pass the connect function a tuple containing the MAC
		# address and port of target
		sock.connect((addr, port))
        # If we succeed, we will know that channel is open and 
		# listing
		print '[+] RFCOMM Port ' + str(port) + ' open'
        sock.close()
    except Exception, e:
        # If connect function throws an exception, we know that 
		# we can't connect to that port and it is closed.
		print '[-] RFCOMM Port ' + str(port) + ' closed'

# Repeat the connection attempt for each of the 30 possile 
# RFCOMM ports
for port in range(1, 30):
    rfcommCon('00:16:38:DE:AD:11', port)
