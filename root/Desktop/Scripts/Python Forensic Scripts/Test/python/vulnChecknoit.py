import socket
def retBanner(ip, port):
	try:
		socket.setdefaulttimeout(2)
		s = socket.socket()
		s.connect((ip, port))
		banner = s.recv(1024)
		return banner
	except:
		return

def checkVulns(banner):
	if 'SSH-1.5-Cisco-1.25' in banner:
		print '[+] Cisco SSH Server is vulnerable.'
	elif '3Com 3CDaemon FTP Server Version 2.0' in banner:
		print '[+] 3CDaemon FTP Server is vulnerable.'
	elif 'Ability Server 2.34' in banner:
		print '[+] Ability FTP Server is vulnerable.'
	elif 'Sami FTP Server 2.0.2' in banner:
		print '[+] Sami FTP Server is vulnerable.'
	else:
		print '[-] FTP Server is not vulnerable.'
	return 

def main():
	ip1 = '10.99.1.2'
	ip2 = '10.99.1.1'
	ip3 = '10.99.1.3'
	port = 21
	banner1 = retBanner(ip1, port)
	if banner1:
		print '[+] ' + ip1 + ': ' + banner1.strip('\n')
		checkVulns(banner1)
	banner2 = retBanner(ip2, port)
	if banner2:
		print '[+] ' + ip2 + ': ' + banner2.strip('\n')
		checkVulns(banner2)
	banner3 = retBanner(ip3, port)
	if banner3:
		print '[+] ' + ip3 + ': ' + banner3.strip('\n')
		checkVulns(banner3)
if __name__ == '__main__':
	main()