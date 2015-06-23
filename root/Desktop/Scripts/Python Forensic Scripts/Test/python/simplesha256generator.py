#
# Python forensics
# Simple program to generate the SHA-256
# one-way crytographic hash of a given string

# Step 1
# Instruct the interpreter to import the
# Standard library module hashlib

import hashlib

# print a message to the user

print
print("Simple program to generate the SHA-256 Hash of the string 'Python Forensics'")
print

# define a string with the desired text
myString = "Python forensics"

# create an object named hash which is of type sha256
hash = hashlib.sha256()

# utilize the update method of the hash object to generate the
# SHA 256 hash of myString

hash.update(myString)

# obtain the generated hex values of the SHA256 Hash
# from the object
# by utilizing the hexdigest method

hexSHA256 = hash.hexdigest()

# print out the result and utilize the upper method 
# to convert all the hex characters to upper case

print("SHA-256 Hash: " + hexSHA256.upper())
print

print("Processing completed")


