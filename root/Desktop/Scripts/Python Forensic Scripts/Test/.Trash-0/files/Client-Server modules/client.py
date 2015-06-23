#
# Client Objective
# 1) Setup a Client Socket
# 2) Attempt a connection to the server on port 5555
# 3) Wait for a reply
# 4) Print out the message received from the server
#
import socket
MAX_BUFFER = 1024
# Creat a Socket
myClientSocket = socket.socket()
# Get my local host address
localHost = socket.gethostname()
# Specify a local Port to attempt a connection
localPort = 5555
# Attempt a connection to my localHost and localPort
myClientSocket.connect((localHost, localPort))
# Wait for a reply
# This is sychronous call, meaning
# that the program will halt until a response is recieved
# or the program will be terminated
msg = myClientSocket.recv(MAX_BUFFER)
print msg
# Close the Socket.  This will terminate the connection
myClientSocket.close()