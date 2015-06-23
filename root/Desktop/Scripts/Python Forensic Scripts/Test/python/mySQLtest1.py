#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys

try:
	# Create a connection to the database
	con = mdb.connect('localhost', 'testuser', 'Nbalive1', 'testdb')
	
	# Create a cursor object to traverse records
	cur = con.cursor()
	# Execute a sql query
	cur.execute("SELECT VERSION()")
	
	# Use fetchone method to retrieve only one record
	ver = cur.fetchone()

	print "Database version: %s " % ver

except _mysql.Error, e:
	
	print "Error %d: %s" % (e.args[0], e.args[1])
	sys.exit(1)

finally:
	
	if con:
		con.close()