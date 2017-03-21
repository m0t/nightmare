#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
GDB debugging interface for Nightmare Fuzzing Project
Created on 2015
@author: joxean
"""

import os
import re
import sys
import time
import ConfigParser

from tempfile import mkstemp,NamedTemporaryFile

dir_name = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(dir_name, ".."))
sys.path.append(os.path.join(dir_name, "../lib"))
sys.path.append(os.path.join(dir_name, "../../runtime"))

from crash_data import CCrashData
from nfp_process import TimeoutCommand
from nfp_log import log

#-----------------------------------------------------------------------
# Default timeout
timeout = 10

#-----------------------------------------------------------------------
class CGDBInterface(object):
  def __init__(self, program, opts = None):
    global dir_name
    global timeout

    self.buf = None
    self.cmdline = program
    self.program = self.cmdline.split(" ")[0]
    self.args = self.cmdline.split(" ")[1:]
    self.conf = opts

    self.gdb_commands = self.generate_cmd_script()
    self.debug = self.conf["debug"]

    if os.getenv("NIGHTMARE_TIMEOUT"):
      timeout = float(os.getenv("NIGHTMARE_TIMEOUT"))
    self.timeout = timeout
    self.signal_blacklist = ["SIGINT"]

    self.pc = None
    self.stack = []
    self.signal = None
    self.disasm = None
    self.disasm_around = []
    self.registers = {}
    self.exploitability_reason = None
    self.exploitability = None

  def read_signal(self, line):
    #Thread 1 "sweep.0" received signal SIGINT, Interrupt.
    #Program received signal SIGINT,
    match = re.match("Program received signal (\w+),", line)
    if not match:
      match = re.match("Thread 1 \"([^\"]+)\" received signal (\w+),", line)
      if not match:
        return
      else:
        self.signal = match.group(2)
    else:
      self.signal = match.group(1)
    return


  def parse_pc(self, pc):
    addr = pc.split(" ")[1]
    
    addr_pos = addr.find(":")
    if addr_pos > -1:
      addr = addr[:addr_pos]

    pos = pc.find(":\t")
    disasm = None

    if pos > -1:
      disasm = pc[pos+2:]
      disasm = disasm.strip(" ").strip("\n").strip("\n")

    try:
      self.pc = addr
      self.pc = int(self.pc, 16)
    except:
      pass

    self.disasm = disasm

  def parse_registers(self, regs):
    for line in regs:
      data = re.findall("(\w+)\W+(.*)\\t", line)
      if not data:
        continue
      
      data = data[0]
      reg = data[0]

      try:
        addr = int(data[1], 16)
      except:
        addr = data[1]
        raise

      self.registers[reg] = addr

  def parse_stack(self, stack):
    pc = True
    for line in stack:
      line = line.strip("\r").strip("\n")
      l = line.split(" ")
      l = l[1:]
      
      for i in range(5):
        if l[i] == "":
          continue
        break

      if not pc:
        try:
          addr = l[i]
          addr = int(addr, 16)
        except:
          pass
      else:
        addr = self.pc
        pc = False

      func = " ".join(l[i+1:])
      self.stack.append([addr, func])

  def parse_disasm(self, disasm):
    for line in disasm:
      pc_crash = False
      if line.startswith("=> "):
        pc_crash = True
        line = line.replace("=> ", "   ")

      ret = re.findall("(\w+) (.*)", line)

      if ret:
        ret = ret[0]
        try:
          addr = ret[0]
          addr = int(addr, 16)
        except:
          pass
        
        data = ret[1]
        self.disasm_around.append([addr, data])

  def set_exploitability(self, exploitability, exploitability_desc):
    self.exploitability = exploitability
    self.exploitability_reason = exploitability_desc

  def parse_dump(self, lines):
    found_crash_start = False
    if len(lines) <= 8:
      return

    for i in range(len(lines)):
      line = lines[i]
      line = line.strip("\r").strip("\n")

      # Ignore various informative messages like thread switching
      if line.startswith("["):
        continue

      # The 1st thing we need to find is the signal message
      if self.signal is None:
        if line.find("received signal") >= 0:
          #print("parsing signal")
          self.read_signal(line)
        #
        continue

      # Skip until the following message is found
      if line.startswith("@@@START-OF-CRASH"):
        found_crash_start = True
        continue

      if found_crash_start:
        if line.startswith("@@@PROGRAM-COUNTER"):
          pc = lines[i+1]
          print("pc: %s" % pc)
          self.parse_pc(pc)
          # Skip the line with the $PC information
          i += 1
        elif line.startswith("@@@EXPLOITABLE"):
          i += 1
          exploitability = None
          exploitability_desc = None
          # Get all the lines with registers data
          while i < len(lines):
            line = lines[i]
            line = line.strip("\r").strip("\n")

            if line.startswith("Description:"):
              exploitability_desc = line[len("Description:")+1:]
            elif line.startswith("Exploitability Classification:"):
              exploitability = line[len("Exploitability Classification:")+1:]

            i += 1
            if line.startswith("@@@"):
              break
          print
          # And fill the internal dictionary with the register values
          self.set_exploitability(exploitability, exploitability_desc)
        elif line.startswith("@@@REGISTERS"):
          i += 1
          regs = []
          # Get all the lines with registers data
          while i < len(lines):
            line = lines[i]
            line = line.strip("\r").strip("\n")

            i += 1
            if line.startswith("@@@"):
              break
            print line
            regs.append(line)
          print
          # And fill the internal dictionary with the register values
          self.parse_registers(regs)
        elif line.startswith("@@@START-OF-STACK-TRACE"):
          i += 1
          stack = []
          # Get all the lines with registers data
          j = 0
          while i < len(lines):
            line = lines[i]
            line = line.strip("\r").strip("\n")

            i += 1
            if line.startswith("@@@END-OF-STACK-TRACE"):
              i += 1
              break
            
            j += 1
            if j <= 5:
              print line
            stack.append(line)

          self.parse_stack(stack)
          continue
        elif line.startswith("@@@START-OF-DISASSEMBLY-AT-PC"):
          i += 1
          disasm = []
          # Get all the disassembly lines
          while i < len(lines):
            line = lines[i]
            line = line.strip("\r").strip("\n")

            i += 1
            if line.startswith("@@@END-OF-DISASSEMBLY-AT-PC"):
              i += 1
              break
            print line
            disasm.append(line)
          self.parse_disasm(disasm)
          continue
        elif line.startswith("@@@END-OF-CRASH"):
          # Finished!
          break

  def got_valid_signal(self):
    if self.signal: 
      if not self.signal in self.signal_blacklist:
        return True
      else:
        log("Target received %s, ignoring" % self.signal )
    return False       

  def generate_cmd_script(self):
    gdb_commands = '''set disassembly-flavor intel
handle SIGPIPE nostop noprint
set follow-fork-mode child
source ../lib/interfaces/ignore-errors.py
run %s >> %s 
info proc cmdline
echo @@@START-OF-CRASH
echo @@@PROGRAM-COUNTER
ignore-errors x /i $pc
echo
echo @@@REGISTERS
i r
echo @@@START-OF-STACK-TRACE
back 128
echo @@@END-OF-STACK-TRACE
echo @@@START-OF-DISASSEMBLY-AT-PC
ignore-errors x /16i $pc-16
echo 
echo @@@END-OF-DISASSEMBLY-AT-PC
echo @@@END-OF-CRASH
quit
    '''
    gdb_commands %= (" ".join(self.args), self.conf["output_file"])
    envs = ""
    for var in self.conf["env"].keys():
      envs += "set environment %s=%s\n" % (var, self.conf["env"][var])
    gdb_commands = envs + gdb_commands

    #save
    self.cmd_file = NamedTemporaryFile(suffix=".gdb")
    self.cmd_file.write(gdb_commands)
    self.cmd_file.flush()
    #print(gdb_commands)
    return self.cmd_file.name

  def debug(self, msg):
    if self.debug:
      print("DEBUG: [%s %d:%d] %s" % (time.asctime(), os.getpid(), thread.get_ident(), msg))
      sys.stdout.flush()

  def run(self):
    os.putenv("LANG", "C")
    
    #logfile = mkstemp()[1]
    try:
      #cmd = '/bin/bash -c "/usr/bin/gdb -q --batch --command=%s --args %s" 2>/dev/null > %s'
      #cmd = '/bin/bash -c "/usr/bin/gdb -q --batch --command=%s --args %s" > %s'
      #cmd %= (self.gdb_commands, self.program, logfile)
      import signal
      signal.signal(signal.SIGTTOU, signal.SIG_IGN)
      cmd = "/usr/bin/gdb -q --batch --command=%s --args %s"
      #print(self.program)
      #print(" ".join(self.args))
      cmd %= (self.gdb_commands, self.program)
      #print cmd

      cmd_obj = TimeoutCommand(cmd)
      cmd_obj.run(self.timeout, get_output=True)
      
      #buf = open(logfile, "rb").readlines()
      target_output = cmd_obj.stdout
      #print(target_output)
      self.parse_dump(target_output.split("\n"))

      if self.got_valid_signal():
        crash_data = CCrashData(self.pc, self.signal)
        i = 0
        for stack in self.stack:
          crash_data.add_data("stack trace", "%d" % i, stack)
          i += 1

        for reg in self.registers:
          crash_data.add_data("registers", reg, self.registers[reg])

        crash_data.add_data("disassembly", int(self.pc), self.disasm)
        for dis in self.disasm_around:
          if type(dis[0]) in (int,long) or dis[0].isdigit():
            crash_data.add_data("disassembly", dis[0], dis[1])
        crash_data.disasm = [self.pc, self.disasm]
        
        if self.exploitability is not None:
          crash_data.exploitable = self.exploitability
        
        if self.exploitability_reason is not None:
          crash_data.add_data("exploitability", "reason", self.exploitability_reason)

        crash_data_buf = crash_data.dump_json()
        crash_data_dict = crash_data.dump_dict()

        print("\nYep, we got a crash! \o/\n")


        return crash_data_dict

      return
    except KeyboardInterrupt:
      exit(-1)
    #finally:
    #  os.remove(logfile)

#-----------------------------------------------------------------------
def read_configuration(cfgfile, cfgsection):
    if not os.path.exists(cfgfile):
      raise Exception("Invalid configuration file given")

    parser = ConfigParser.SafeConfigParser()
    parser.optionxform = str
    parser.read(cfgfile)

    gdb_conf = {}
    gdb_conf["output_file"] = "/tmp/gdb-target-output.log"
    gdb_conf["debug"] = False

    if cfgsection not in parser.sections():
      raise Exception("Section %s does not exist in the given configuration file" % self.section)
    
    try:
      gdb_conf["output_file"] = parser.get(cfgsection, 'gdb-target-outfile')
    except:
      pass

    try:
      gdb_conf["debug"] = parser.get(cfgsection, 'debug')
    except:
      pass

    gdb_conf["env"] = { "MALLOC_CHECK_":0 }
    try:
      target_env= parser.get(cfgsection, 'environment')

      for item in parser.items(target_env):
        gdb_conf["env"][item[0]] = item[1]
    except:
      pass

    return gdb_conf

def main(args, opts=None, gdb_commands=None):
  if args[0] in ["--attach", "-A"]:
    raise Exception("GDB interface doesn't support attaching")
  else:
    prog = args
    if type(args) is list:
      prog = " ".join(args)

  iface = CGDBInterface(prog, opts=opts)
  return iface.run()

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<program> <file>"

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1:])
