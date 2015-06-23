#!/usr/bin/env python

import _ping
import sys
import socket

upHosts = []
def pingScan(tgtNet):
    
    for x in range(1, 20):
        ipAddress = tgtNet + '.' + str(x)
        
        delay = _ping.do_one(ipAddress, timeout=0.2)
        
        if delay !=None:
            upHosts.append(ipAddress)
    return upHosts
            
def main():
    
    tgtNet = '192.168.0'
    pingScan(tgtNet)
    print upHosts
    
if __name__ == '__main__':
    main()