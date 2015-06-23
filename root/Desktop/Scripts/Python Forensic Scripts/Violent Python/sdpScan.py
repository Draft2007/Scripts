#!/usr/bin/python
# -*- coding: utf-8 -*-
from bluetooth import *

# Browsing SDP profile of a Bluetooth device describes the services
# running on each unique Bluetooth protocol and port
def sdpBrowse(addr):
    services = find_service(address=addr)
    for service in services:
        name = service['name']
        proto = service['protocol']
        port = str(service['port'])
        print '[+] Found ' + str(name) + ' on ' + str(proto) + ':' + port


sdpBrowse('00:16:38:DE:AD:11')
