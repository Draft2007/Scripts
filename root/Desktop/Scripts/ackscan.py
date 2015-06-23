from scapy.all import *
import os, sys




def ackScan(ipadr):
	iplayer = IP(dest=ipadr)
	tcplayer = TCP(flags="A", ack="0", dport=80)
	pkt = IP / TCP
	sr1(pkt, verbose=0)
	








def main():
	ipadr = "10.99.1.5"
	ackScan(ipadr)
	

	
if __name__ == "__main__":
	main()
