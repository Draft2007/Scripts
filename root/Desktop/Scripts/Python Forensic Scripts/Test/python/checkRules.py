import sys

def checkRules(pkt):
	if pkt:
		print pkt.getlayer('%Raw.load%')
	else:
		pass
