#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Nightmare Fuzzing Project
@author: joxean
"""

import os
import sys
import time
import psutil
import threading
import subprocess

from multiprocessing import Process, cpu_count

from nfp_log import log, debug

#-----------------------------------------------------------------------
# Dict of return codes to signals that we're interested on.
RETURN_SIGNALS = {}
RETURN_SIGNALS[138] = "SIGBUS"
RETURN_SIGNALS[139] = "SIGSEGV"
RETURN_SIGNALS[136] = "SIGFPE"
RETURN_SIGNALS[134] = "SIGABRT"
RETURN_SIGNALS[133] = "SIGTRAP"
RETURN_SIGNALS[132] = "SIGILL"
RETURN_SIGNALS[143] = "SIGTERM"
# These are the usual return codes for crashing Windows programs. Do we
# need to add more codes?
RETURN_SIGNALS[0xC0000005] = "ACCESS_VIOLATION"
RETURN_SIGNALS[0xC0000094] = "INTEGER_DIVIDE_BY_ZERO"
RETURN_SIGNALS[0xC0000095] = "INTEGER_OVERFLOW"
RETURN_SIGNALS[0xC0000096] = "PRIVILEGED_INSTRUCTION"
RETURN_SIGNALS[0xC00000FD] = "STACK_OVERFLOW"

#-----------------------------------------------------------------------
def process_manager(total_procs, target, args, wait_time=0.2):
  """ Always maintain a total of @total_procs running @target and
     waiting for each thread to finish @wait_time second(s). """
  procs = []
  debug("Maximum number of processes in pool is %d" % total_procs)
  try:
    while 1:
      if len(procs) < total_procs:
        debug("Starting process %d" % (len(procs)+1))
        p = Process(target=target, args=args)
        p.start()
        procs.append(p)
        debug("Total of %d process(es) started" % len(procs))
      else:
        i = 0
        for p in list(procs):
          p.join(wait_time)
          if not p.is_alive():
            debug("Process finished, deleting and starting a new one...")
            del procs[i]
            continue
          i += 1
  except KeyboardInterrupt:
    pass

#-----------------------------------------------------------------------
class TimeoutCommand(object):
  """ Execute a command specified by @cmd and wait until a maximum of
      @timeout seconds. If the timeout is reached, the process is then
      killed. """
  def __init__(self, cmd):
    self.cmd = cmd
    self.process = None
    
    self.stderr = None
    self.stdout = None

    # It's only used when timeout is set to "auto"
    self.default_timeout = 60
    self.thread = None
    self.pid = None
    self.cpu_killed = False

  def check_cpu(self):
    while True:
      try:
        if self.pid is None:
          time.sleep(0.2)
          continue

        proc = psutil.Process(self.pid)
        cpu = 0
        l = []
        for x in xrange(20):
          tmp = int(proc.cpu_percent(interval=0.1))
          cpu += tmp
          l.append(tmp)

        if cpu is not None and (cpu <= 100 or l.count(0) > 10):
          log("CPU at 0%, killing")
          self.cpu_killed = True
          self.do_kill()
          break
        else:
          time.sleep(0.5)
      except psutil.NoSuchProcess:
        break

  def do_kill(self):
    self.process.terminate()
    self.process.terminate()
    self.process.kill()
    while psutil.pid_exists(self.pid):
      log("Process %d stuck, trying to kill" % self.pid)
      self.process.kill()
      time.sleep(0.1)
    self.process.wait()

  def run(self, timeout=60, get_output=False):
    def target():
      debug('Thread started')
      if os.name == "nt":
        line = self.cmd
        shell = False
      else: # Unix based
        #line = "exec %s" % self.cmd # removing this seems to avoid SIGTTOU being sent to the process
        line = self.cmd.split(" ")
        shell = False
      
      if get_output:
        self.process = subprocess.Popen(line, stdout=subprocess.PIPE,\
                                      stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=shell)
        self.pid = self.process.pid
        out, err = self.process.communicate()
        self.stdout = out
        self.stderr = err
      else:
        self.process = subprocess.Popen(line, shell=shell)
        self.pid = self.process.pid
        self.process.communicate()

      debug('Thread finished')

    thread = threading.Thread(target=target)
    thread.start()

    if str(timeout).lower() == "auto":
      self.thread = threading.Thread(target=self.check_cpu)
      self.thread.start()
      thread.join(self.default_timeout)
    else:
      thread.join(timeout)

    if thread.is_alive():
      log('Terminating process after timeout (%s)' % str(timeout))
      try:
        self.do_kill()
      except:
        log("Error killing process: %s" % str(sys.exc_info()[1]))

      thread.join()

    self.process.wait()
    ret = self.process.returncode

    # A negative return code means a signal was received and the return
    # code is -1 * SIGNAL. Return the expected Unix return code.
    if ret is not None and ret < 0:
      if os.name == "nt":
        ret = ret & 0xFFFFFFFF
      else:
        ret = abs(ret) + 128
    return ret

#-----------------------------------------------------------------------
def do_nothing():
  try:
    import time
    print time.asctime()
    time.sleep(1)
  except KeyboardInterrupt:
    print "Aborted."

if __name__ == "__main__":
  process_manager(2, do_nothing, [], 1)
