set disassembly-flavor intel
set environment MALLOC_CHECK_=2
handle SIGPIPE nostop noprint
set follow-fork-mode child

source ../lib/interfaces/ignore-errors.py
run
echo @@@START-OF-CRASH\n

echo @@@PROGRAM-COUNTER\n

ignore-errors x /i $pc
echo \n
echo @@@REGISTERS\n
i r
echo @@@START-OF-STACK-TRACE\n

back 128

echo @@@END-OF-STACK-TRACE\n

echo @@@START-OF-DISASSEMBLY-AT-PC\n

ignore-errors x /16i $pc-16
echo \n
echo @@@END-OF-DISASSEMBLY-AT-PC\n

echo @@@END-OF-CRASH\n

quit
