#!/bin/sh

ls *.pem | while read pbk; do rm $pbk; done
ls *.token | while read toke; do rm $toke; done
echo '[*] Keys Deleted'

# EOF
