#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect('localhost', 'testuser', 'Nbalive1', 'testdb')

with con:
	
	cur = con.cursor()
	cur.execute("SELECT * FROM Writers")

	rows = cur.fetchall()

	for row in rows:
		print row
	