import MySQLdb as mdb


ipObservations = []
ipObservations.append("TCP")
ipObservations.append("192.168.1.1")
ipObservations.append("69")
ipObservations.append("1.1.1.1")
ipObservations.append("11")

con = mdb.connect('192.168.1.98', 'root', 'Nbalive1', 'assetinventory')

for packet in ipObservations:
    cur = con.cursor()
    cur.execute("INSERT INTO netflow (protocol,srcip,srcport,destip,destport) \
            VALUES(%s,%s,%s,%s,%s)", (packet[0], packet[1], packet[2], packet[3], packet[4]))