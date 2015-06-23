#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect('localhost', 'testuser', 'Nbalive1', 'testdb')

with con:
	
	cur = con.cursor(mdb.cursors.DictCursor)
	cur.execute("SELECT * FROM Writers LIMIT 4")

	rows = cur.fetchall()

	for row in rows:
		print row["Id"], row["Name"]
	
	