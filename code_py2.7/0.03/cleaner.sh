#!/bin/sh
echo '============================================================'
ls *.pem | while read pbk; do rm $pbk >> /dev/null 2>&1 ; done
ls *.token | while read toke; do rm $toke >> /dev/null 2>&1 ; done
ls *.shares | while read share; do rm $share >> /dev/null 2>&1 ; done
ls *.pyc | while read c; do rm $c >> /dev/null 2>&1 ; done
rm 2 >> /dev/null 2>&1

echo '[*] Keys Deleted'
python client.py log
# EOF