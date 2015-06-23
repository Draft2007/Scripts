#!/usr/bin/python

import socket
import getopt
import sys

import __builtin__
from scapy.all import *
conf.verb = 0

scapy_builtins = __import__("scapy.all",globals(),locals(),".").__dict__
__builtin__.__dict__.update(scapy_builtins)

class StealthException(Exception):
   def __init__(self, value):
      self.value = value

   def __str__(self):
      return repr(self.value)

class Stealth(object):
   SynPacket, XmasPacket, FinPacket, NullPacket = range(4)

   @staticmethod
   def scan(source, target, ports, packetType):
      try:
         for port in ports:
            packet = None
            if packetType == Stealth.SynPacket:
               # Setup a syn packet.
               packet = IP(dst=target, src=source)/TCP(dport=int(port), flags="S", seq=40)
            elif packetType == Stealth.XmasPacket:
               # Setup a xmas packet.
               packet = IP(dst=target)/TCP(dport=int(port), flags="FPU", seq=40)
            elif packetType == Stealth.FinPacket:
               # Setup a fin packet.
               packet = IP(dst=target)/TCP(dport=int(port), flags="F", seq=40)
            elif packetType == Stealth.NullPacket:
               # Setup a null packet.
               packet = IP(dst=target)/TCP(dport=int(port), flags="", seq=40)

            # Finally send the packet.
            result = sr1(packet,timeout=1)
            
            if not result:
               print "\n"+str(port)+":closed\n"
            else:
               print "\n"+str(port)+":open\n"
      except Exception as e:
         raise StealthException(
            "Failed to send packet to {0}: {1}".format(target, str(e)))

def usage():
   print "Usage: python stealth.py <ip> <ports> -p=<type>\n\n" \
      "CAUTION! On most systems you must run this script as root!\n\n" \
      "<ip>\t\tSpecifies the ip address the packet is send to.\n\n" \
      "<ports>\t\tA comma seperated string specifying ports to scan.\n\n" \
      "--p|--packet\tSpecifies the packet type (possible types are f, x, s, n).\n" \
      "\n x : Sends a xmas packet.\n" \
      "\n s : Sends a syn packet.\n" \
      "\n n : Sends a null packet.\n" \
      "\n f : Sends a fin packet.\n\n"

def main():
   try:
      if len(sys.argv) < 4:
         print "To few arguments found!"
         usage()
         sys.exit()
         
      print sys.argv
      
      source = sys.argv[1]
      target = sys.argv[2]
      ports = sys.argv[3].split(',')
      opts, args = getopt.getopt(sys.argv[4:], 'hp:', ["packet=", "help"])
      print opts, args
   except getopt.GetoptError as err:
      print str(err)
      usage()
      sys.exit(2)

   packet = None
   for o, a in opts:
      if o in ("--packet"):
         if a == 's':
            packet = Stealth.SynPacket
         elif a == 'x':
            packet = Stealth.XmasPacket
         elif a == 'f':
            packet = Stealth.FinPacket
         elif a == 'n':
            packet = Stealth.NullPacket
      elif o in ("-h", "--help"):
         usage()
         sys.exit()
      else:
         assert False, "Unhandled option!"

   if target == None:
      print "No ip given, which is a required argument!"
      usage()
      sys.exit()
   if ports == None or len(ports) == 0:
      print "No ports given, this is a required argument!"
      usage()
      sys.exit()
   if source == None:
      print "No source ip given, which is a required argument!"
      usage()
      sys.exit()	
   elif packet == None:
      print "No packet type given!"
      usage()
      sys.exit()

   try:
      Stealth.scan(source, target, ports, packet)
   except StealthException as e:
      print e.value

if __name__ == "__main__":
    main()
