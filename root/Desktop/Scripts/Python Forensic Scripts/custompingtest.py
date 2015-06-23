import socket
import getopt
import sys
import __builtin__
from scapy.all import *
conf.verb = 0
scapy_builtins = __import__("scapy.all",globals(),locals(),".").__dict__
__builtin__.__dict__.update(scapy_builtins)

packet = IP(dst=10.99.1.2)/TCP(dport=int(22), flags="F", seq=40)
ping = sr1(packet, timeout=1)
ping()
