#!/bin/sh

v=0
if [ $# -eq 1 ]
then
    case $1 in
        '-v')
            v=1
        ;;
        *)
            echo 'Unrecognized Option!'
            exit
        ;;
    esac
fi

nx_iface=$(ifconfig | grep BROADCAST | grep RUNNING | cut -d ':' -f 1)
private_ip=$(ifconfig | grep 'inet ' | grep broadcast | cut -d ' ' -f 10)
public_ip=$(curl -s https://api.ipify.org)

if [ $v -eq 1 ]; then
    echo 'Public IP: '$public_ip
    echo 'Private IP: '$private_ip
fi

touch nx.txt
echo 'Public IP:\t'$public_ip >> nx.txt
echo 'Private IP:\t'$private_ip >> nx.txt
echo 'Nx Iface:\t'$nx_iface >> nx.txt
# EOF