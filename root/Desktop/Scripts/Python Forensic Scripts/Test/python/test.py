# Specify the Base Network Address (the first 3 octets)
ipBase = '192.168.0.'

# Next Create an Empty List that will hold the completed
# list of IP addresses
ipList = []

# Finally, loop through the possible list of local host
# addresses 0-255 using range function.
# Then append each complete address to the ipList
# Notive that I use the str(ip) function in order to
# concatenate the string ipBase with list of numbers 0-255
for ip in range(0,256):
    ipList.append(ipBase+str(ip))
    print ipList.pop()