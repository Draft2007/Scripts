import socket
import os
from netaddr import IPNetwork,IPAddress


# host to listen on
host = "192.168.1.98"
subnet = "192.168.1.0/24"
magic_message = "PYTHONRULES!"

# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

def sniffer():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol) 
    sniffer.bind((host, 0))

    # we want the IP headers included in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if we're on Windows we need to send an IOCTL
    # to setup promiscuous mode
    if os.name == "nt": 
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # read in a single packet
    raw_buffer = sniffer.recvfrom(65565)
    print raw_buffer
    # if we're on Windows turn off promiscuous mode
    if os.name == "nt": 
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
def udp_sender(subnet,magic_message):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message,("%s" % ip,65212))
        except:
            pass
sniffer()
udp_sender(subnet, magic_message)