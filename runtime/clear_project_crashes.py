#!/usr/bin/python
import MySQLdb
import sys

db="nightmare"
user="fuzzing"
passwd="fuzzing"

if len(sys.argv) < 2:
	print("usage: %s <project name>")
	exit(-1)

db = MySQLdb.connect(host="localhost", user=user, passwd=passwd, db=db)        

cur = db.cursor()

select = "SELECT project_id FROM projects p WHERE p.name = %s"
cur.execute(select, (sys.argv[1]) )

pr_id=cur.fetchall()[0][0]

del_stmt="DELETE FROM crashes WHERE project_id = %s"
cur.execute(del_stmt, (pr_id))
db.commit()

#for row in cur.fetchall():
#    for c in row:
#    	sys.stdout.write("%s | " % c)
#    print()

db.close()