#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
from bluetooth import *


def retBtAddr(addr):
    # Constructs the MAC of the Bluetooth radio by incrementing
	# by one
	btAddr=str(hex(int(addr.replace(':', ''), 16) + 1))[2:]
    btAddr=btAddr[0:2]+":"+btAddr[2:4]+":"+btAddr[4:6]+":"+\
    btAddr[6:8]+":"+btAddr[8:10]+":"+btAddr[10:12]
    return btAddr

def checkBluetooth(btAddr):
    btName = lookup_name(btAddr)
    if btName:
        print '[+] Detected Bluetooth Device: ' + btName
    else:
        print '[-] Failed to Detect Bluetooth Device.'


def wifiPrint(pkt):
    # Listens for 802.11 frame with MAC address matching first
	# three bytes of an iPhone 4S
	iPhone_OUI = 'd0:23:db'
    if pkt.haslayer(Dot11):
        # Extracts the wifi MAC address and stores as variable
		# wifiMAC
		wifiMAC = pkt.getlayer(Dot11).addr2
        if iPhone_OUI == wifiMAC[:8]:
            # Prints the Detected MAC address
			print '[*] Detected iPhone MAC: ' + wifiMAC
            # 
			btAddr = retBtAddr(wifiMAC)
            print '[+] Testing Bluetooth MAC: ' + btAddr
            checkBluetooth(btAddr)


conf.iface = 'mon0'
sniff(prn=wifiPrint)
