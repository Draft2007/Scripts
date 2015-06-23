#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect('localhost', 'testuser', 'Nbalive1', 'testdb')

with con:
	
	cur = con.cursor()
	cur.execute("SELECT * FROM Writers LIMIT 5")

	rows = cur.fetchall()
	
	# Returns information about each of the result columns
	# of the query
	desc = cur.description
	
	# Print and format the table column names
	print "%s %3s" % (desc[0][0], desc[1][0])

	for row in rows:
		print "%2s %3s" % row
	
	