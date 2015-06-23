#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect('localhost', 'testuser', 'Nbalive1', 'testdb')

with con:
	
	cur = con.cursor()
	cur.execute("DROP TABLE IF EXISTS Writers")
	cur.execute("CREATE TABLE Writers(Id INT PRIMARY KEY AUTO_INCREMENT, Name VARCHAR (25))")
	cur.execute("INSERT INTO Writers(Name) VALUES('Jack London')")
	cur.execute("INSERT INTO Writers(Name) VALUES('Honore de Balzac')")
	cur.execute("INSERT INTO Writers(Name) VALUES('Lion Feuchtwanger')")
	cur.execute("INSERT INTO Writers(Name) VALUES('Emile Zola')")
	cur.execute("INSERT INTO Writers(Name) VALUES('Truman Capote')")