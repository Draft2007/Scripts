#!/usr/bin/python
# -*- coding: utf-8 -*-

import _mysql
import sys

try:
    con = _mysql.connect('192.168.1.98', 'root', 'Nbalive1', 'assetinventory')

    con.query("SELECT VERSION()")
    result = con.use_result()

    print "MySQL version: %s" % \
          result.fetch_row()[0]

except _mysql.Error, e:

    print "Error %d: %s" % (e.args[0], e.args[1])
    sys.exit(1)

finally:

    if con:
        con.close()