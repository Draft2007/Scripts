import socket

target_host = "127.0.0.1"
target_port = 80

def udpClient():
    
    # create a socket object using standard IPv4 or hostname, but
    # uses SOCK_DGRAM to indicate UDP
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # send some data
    client.sendto("AAABBBCCC", (target_host, target_port))
    
    # receive some data
    data, addr = client.recvfrom(4096)
    
    print data

def main():
    udpClient()

if __name__ == '__main__':
    main()
