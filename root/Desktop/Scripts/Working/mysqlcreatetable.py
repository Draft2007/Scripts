#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect('192.168.1.98', 'root', 'Nbalive1', 'assetinventory');

with con:

    cur = con.cursor()
    cur.execute("CREATE TABLE netflow(Id INT PRIMARY KEY AUTO_INCREMENT, \
                 protocol VARCHAR(25), \
                 srcip VARCHAR(25), \
                 srcport VARCHAR(25), \
                 destip VARCHAR(25), \
                 destport VARCHAR(25) \
                 )")
    print "Table created successfully"
    