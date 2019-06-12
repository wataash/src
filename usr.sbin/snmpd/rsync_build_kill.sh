#!/bin/sh

set -eu

rsync -va -e 'ssh -p 10622' \
    --include='Makefile' --include='*.c' --include='*.h' --exclude='*' \
    -h --progress \
    ~/src/openbsd/src/usr.sbin/snmpd/  root@localhost:~/src/snmpd/
ssh -p10622 root@localhost 'cd ~/src/snmpd/; make'
ssh -p10622 root@localhost 'pkill -9 snmp' || true
