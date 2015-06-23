#!/usr/bin/python

import socket
import getopt
import sys

import __builtin__
from scapy.all import *
conf.verb = 0

scapy_builtins = __import__("scapy.all",globals(),locals(),".").__dict__
__builtin__.__dict__.update(scapy_builtins)

class ScannerException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
    
class Scanner(object):
    ackPacket, synPacket = range(2)
    
    @staticmethod
    def scan(target, ports, packetType):
        
        try:
            for port in ports:
                
                if packetType == Scanner.ackPacket:
                    packet = IP(dst=target)/TCP(dport=int(port), flags="A", seq=40)
		    
                elif packetType == Scanner.synPacket:
                    packet = IP(dst=target)/TCP(dport=int(port), flags="S", seq=40)
               
                result = sr1(packet,timeout=1)
                flag = result.sprintf("%TCP.flags%")
                if flag == 'SA':
                    print str(flag)
		    if packetType == Scanner.synPacket:
			print "Port is Open"
		    else:
			print "Port is Closed"
		else:
		    print "Port is Closed"
            
        except Exception as e:
            raise StealthException("Failed to send packet to {0}: {1}".format(target, str(e)))        

def usageHelper():
    print "Usage: python scanner.py <ip> <ports> -p=<type>\n\n" \
        "CAUTION! On most systems you must run this script as root!\n\n" \
        "<ip>\t\tSpecifies the ip address the packet is send to.\n\n" \
        "<ports>\t\tA comma seperated string specifying ports to scan.\n\n" \
        "--p|--packet\tSpecifies the packet type (possible types are f, x, s, n).\n" \
        "\n a : Sends a xmas packet.\n" \
        "\n s : Sends a syn packet.\n" 
              
def main():
    try:
        if len(sys.argv) < 3:
            print "Too few arguments found!"
            usageHelper()
            sys.exit()
                
        print sys.argv
            
        target = sys.argv[1]
        ports = sys.argv[2].split(',')
        opts, args = getopt.getopt(sys.argv[3:], 'hp:', ["packet=", "help"])
        print opts, args
    except getopt.GetoptError as err:
        print str(err)
        usageHelper()
        sys.exit(2)
        
    packet = None
    for o, a in opts:
        if o in ("--packet"):
            if a == 'a':
                packet = Scanner.ackPacket
            elif a == 's':
                packet = Scanner.synPacket
        elif o in ("-h", "--help"):
            usageHelper()
            sys.exit()
        else:
            assert False, "Unhandled option!"
        
    if target == None:
        print "No ip given, which is a required argument!"
        usageHelper()
        sys.exit()
    if ports == None or len(ports) == 0:
        print "No ports given, this is a required argument!"
        usageHelper()
        sys.exit()
    elif packet == None:
        print "No packet type given!"
        usageHelper()
        sys.exit()
        
    try:
        Scanner.scan(target, ports, packet)
    except ScannerException as e:
        print e.value

if __name__ == "__main__":
    main()
            
            