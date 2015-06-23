# define a variable to hold a string representing the base address
baseAddress = "192.168.0."
# next define a list of host addresses using the range
# standard library function (this will give us values of 1-19)
hostAddresses = range(20)
# define a list that will hold the result ip strings
# this starts out as a simple empty list
ipRange = []
# loop through the host addresses since the list hostAddresses
# contains integers from 0-19 and we can create
# a loop in Python that processes each of the list elements
# stored in hostAddresses where i is the loop counter value
for i in hostAddresses:
# append the combined ip strings to the ipRange list
# because ipRange is a list object, the object has a set of 
# attributes and methods.  We are going to invoke the append method 
# each time through the loop and concatenate the base address
# string with the string value of the integer
     ipRange.append(baseAddress+str(i))

for ipAddr in ipRange:
     print ipAddr