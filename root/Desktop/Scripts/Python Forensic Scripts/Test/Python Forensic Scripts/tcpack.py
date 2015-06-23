#!/usr/bin/python

import socket
import getopt
import sys

import __builtin__
from scapy.all import *

scapy_builtins = __import__("scapy.all",globals(),locals(),".").__dict__
__builtin__.__dict__.update(scapy_builtins)

class TcpackException(Exception):
   def __init__(self, value):
      self.value = value

   def __str__(self):
      return repr(self.value)

class Tcpack(object):
   SynPacket, XmasPacket, FinPacket, NullPacket = range(4)

   @staticmethod
   def send(target, packetType):
      try:
         if packetType == Tcpack.SynPacket:
            # Setup a syn packet.
            packet = IP(dst=target)/TCP(dport=80, flags="S")
         elif packetType == Tcpack.XmasPacket:
            # Setup a xmas packet.
            packet = IP(dst=target)/TCP(dport=80, flags="FPU")
         elif packetType == Tcpack.FinPacket:
            # Setup a fin packet.
            packet = IP(dst=target)/TCP(dport=80, flags="F")
         elif packetType == Tcpack.NullPacket:
            # Setup a null packet.
            packet = IP(dst=target)/TCP(dport=80, flags="")

         # Finally send the packet.
         send(packet)
         packet.display()
      except Exception as e:
         raise TcpackException(
            "Failed to send packet to {0}: {1}".format(target, str(e)))

def usage():
   print "Usage: python tcpack.py <ip> [-f] [-x] [-s] [-n]\n\n" \
      "CAUTION! On most systems you must run this script as root!\n\n" \
      "<ip>\t\tSpecifies the ip address the packet is send to.\n\n" \
      "-f|--fin\tSends a fin packet.\n\n" \
      "-x|--xmas\tSends a xmas packet.\n\n" \
      "-s|--syn\tSends a syn packet.\n\n" \
      "-n|--null\tSends a null packet.\n\n" \
      "-h|--help\tDisplays this help page.\n\n" \

def main():
   try:
      target = sys.argv[1]
      opts, args = getopt.getopt(sys.argv[2:], "hsxnf", ["help", "syn", "xmas", "null", "fin"])
   except getopt.GetoptError as err:
      print str(err)
      usage()
      sys.exit(2)

   packets = []
   for o, a in opts:
      if o in ("-s", "--syn"):
         packets.append(Tcpack.SynPacket)
      elif o in ("-x", "--xmas"):
         packets.append(Tcpack.XmasPacket)
      elif o in ("-f", "--fin"):
         packets.append(Tcpack.FinPacket)
      elif o in ("-n", "--null"):
         packets.append(Tcpack.NullPacket)
      elif o in ("-h", "--help"):
         usage()
         sys.exit()
      else:
         assert False, "Unhandled option!"

   if target == None:
      print "No ip given, which is a required argument!"
      usage()
      sys.exit()
   elif len(packets) == 0:
      print "No packet type given, please specify at least one packet type!"
      usage()
      sys.exit()

   try:
      for p in packets:
         Tcpack.send(target, p)
   except TcpackException as e:
      print e.value

if __name__ == "__main__":
    main()
