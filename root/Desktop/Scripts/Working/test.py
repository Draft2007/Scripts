import _ping
import os
import sys
import socket


cTgts = []
def pingScan(network):
    
    for ip in range(1,20):
        tgt = network + '.' + str(ip)
    
        delay = _ping.do_one(tgt, timeout=0.2)
    
        if delay !=None:
            cTgts.append(tgt)
    
        else:
            pass
    return cTgts
        

def portScan(tgt):
    for port in range(1,125):
        try:
            connSkt = socket.socket()
            connSkt.connect((tgt, port))
            connSkt.send('ViolentPython\r\n')
            results = connSkt.recv(100)
        
            print '[+] %d/tcp open' % port
            print '[+] ' + str(results)
        except:
        
            print '[-] %d/tcp closed' % port
        finally:
        
            connSkt.close()	



def main():
    
    network = "192.168.0"
    pingScan(network)
    
    for tgt in cTgts:
        portScan(tgt)
if __name__ == "__main__":
    main()