#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import os
import sys


def retBanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        print banner
        return banner
    except:
        print "Socket not opened"
        return
    
def main():
    ip = '192.168.0.1'
    port = 80
    retBanner(ip, port)
   
if __name__ == '__main__':
    main()