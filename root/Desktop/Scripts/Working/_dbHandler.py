#!/usr/bin/python
# -*- coding: utf-8 -*-
import _mysql
import sys

class _DBWriter:
    def __init__(self, fileName):
        try:
            # create a database object
            self.con = _mysql.connect('192.168.1.98', 'root', 'Nbalive1', 'assetinventory')
        except:
            log.error('MySQL Connection Error')

    def writeDBRow(self, row):
        self.cur = self.con.cursor()
        self.cur.execute("INSERT INTO netflow (protocol,srcip,srcport,destip,destport), \
        VALUES(%s,%s,%s,%s,%s)", (row[0], row[1], str(row[2]), row[3], str(row[4])))
    

    def __del__(self):
        self.con.close()