#!/usr/bin/python

import socket
import os
import struct
import MySQLdb as mdb
from scapy.all import *

from threading import *
from nmap import *

host = "192.168.1.98"
network = "192.168.1."
tgtPort = "0"
ipRange = []
liveHosts = []

con = mdb.connect('192.168.1.98', 'root', 'Nbalive1', 'assetinventory')
       
def nmapScan(ip, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(hosts=ip, arguments='-sU -p0 -T5')
    try:
        state=nmScan[ip]['udp'][int(tgtPort)]['state']
        print "Host Up: %s : %s" % (ip,state)
        liveHosts.append(ip)
        cur = con.cursor()
        cur.execute("INSERT INTO assets (ipaddress) \
                   VALUES(%s)", (ip))
        con.commit()    
    except:
        pass
    nmScan2 = nmap.PortScanner()
    for h in liveHosts:
        for p in range(1,10000):
            packet = IP(dst=h)/TCP(dport=int(p), flags="F", seq=40)
            result = sr1(packet,timeout=0.1)
            if result:
                print "\n"+str(port)+":open\n"
            else:
                pass     
  
        
for i in range(1,255):
    ipRange.append(network+str(i))
#print ipRange   
for ip in ipRange:
    t = Thread(target=nmapScan, args=(ip,tgtPort))
    t.start()
for target in liveHosts:
    scan2 = nmap.PortScanner()
    scan2.scan(hosts=target, ports='1-65535')
    print scan2.scanstats.self()


    
    