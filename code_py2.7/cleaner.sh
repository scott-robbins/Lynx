#!/bin/sh
echo '============================================================'
ls *.pem | while read pbk; do rm $pbk >> /dev/null 2>&1 ; done
ls *.token | while read toke; do rm $toke >> /dev/null 2>&1 ; done
echo '[*] Keys Deleted'
python client.py log
# EOF
