import socket

target_host = "127.0.0.1"
target_port = 9999

def tcpClient():
    
    # creates a socket object, using standard IPv4 or hostname
    # SOCK_STREAM indicates this will be a TCP client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # connect the client
    client.connect((target_host,target_port))
    
    # send some data
    client.send("GET / HTTP/1.1\r\nHost: optimuminfosec.com\r\n\r\n")
    
    # receive some data
    response = client.recv(4096)
    
    print response
    
def main():
    tcpClient()
    
if __name__ == '__main__':
    main()
    