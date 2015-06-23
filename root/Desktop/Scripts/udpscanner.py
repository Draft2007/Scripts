import socket
import os
import struct
import threading
import MySQLdb as mdb

from socket import *
from netaddr import IPNetwork,IPAddress
from ctypes import *

# global variables
host   = "192.168.1.98"
subnet = "192.168.1.0/24"
magic_message = "PYTHONRULES!"

def udp_sender(subnet,magic_message):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message,("%s" % ip,65212))
        except:
            pass
        
def sniff_test(sniffer):
    sniffer.bind((host, 0))
    # we want the IP headers included in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)    
    # read in a single packet
    raw_buffer = sniffer.recvfrom(65565)[0]
    print raw_buffer
                            
def main():
    sniffer = socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    t1 = threading.Thread(target=sniff_test, args=(sniffer))
    t2 = threading.Thread(target=udp_sender, args=(subnet, magic_message))
    t1.start()
    t2.start()
    
main()
    