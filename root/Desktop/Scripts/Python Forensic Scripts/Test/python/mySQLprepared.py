#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect('localhost', 'testuser', 'Nbalive1', 'testdb')

with con:
	
	cur = con.cursor()
	# This will change the name of the author on the 
	# fourth row
	cur.execute("UPDATE Writers SET Name = %s WHERE Id = %s", ("Guy de Maupasant", "4"))

	print "Number of rows updated:", cur.rowcount
	
	