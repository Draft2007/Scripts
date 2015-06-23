

def buildPacket(pkt):
    if pkt.haslayer(Ether):
        ether = pkt.getlayer(Ether)
    else:
        pass
    
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
    else:
        pass
    
    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
    else:
        pass
    
    if pkt.haslayer(UDP):
        udp = pkt.getlayer(UDP)
    else:
        pass
    
    if pkt.haslayer(ICMP):
        icmp = pkt.getlayer(ICMP)
    else:
        pass
    
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
    else:
        pass
    
    if pkt.haslayer(Dot11Beacon):
        dot11bea = pkt.getlayer(Dot11Beacon)
    else:
        pass

    if pkt.haslayer(Dot11ProbeResp):
        dot11resp = pkt.getlayer(Dot11ProbeResp)
    else:
        pass
    
    if pkt.haslayer(RadioTap):
        radiotap = pkt.getlayer(RadioTap)
    else:
        pass
    
    if pkt.haslayer(SNAP):
        snap = pkt.getlayer(SNAP)
    else:
        pass
    
    if pkt.haslayer(LLC):
        llc = pkt.getlayer(LLC)
    else:
        pass
    print ether.src
