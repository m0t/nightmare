#!/usr/bin/python

import subprocess
import sys

#lets clean out some junk immediately
print("%s called" % sys.argv[0])
procs_list = subprocess.check_output("ps ax|sed -r 's/ +/ /g'|sed -r 's/^ +//g'", shell=True)
for l in procs_list.splitlines():
	s = l.split(" ")
	if s[2] == 'T':
		print("Found stopped process, killing PID %s, proc: %s" % (s[0], s[4]))
		try:
			print subprocess.check_output("kill -9 %s" % s[0], shell=True)
		except subprocess.CalledProcessError:
			print("Failed to kill PID %s" % s[0])
			#exit(-1)
			continue
