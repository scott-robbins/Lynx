#!/bin/bash

add_hosts_prompt () {
    echo 'Would you like to add a known host? (y/n)'
    read option

    case $option in
    "y")
        echo 'How Many Hosts are you adding: ';
        read N
        add_hosts $N
        return 1
    ;;
    "n")
        echo 'OK. Moving On...';
        return 0
    ;;
    *)
        echo 'Unrecognized Option!?';
        return 0
    ;;
    esac
}

add_hosts () {
    n_added=0
    while [ $n_added -lt $1 ]
    do
        echo 'Enter IP Address:'
        read IP
        add_host $IP
        n_added=$(( $n_added + 1 ))
        continue=$result
    done
    return $n_added
}

add_host () {
    python client.py add $1
}

# Remove Old Cruft
sh cleaner.sh >> /dev/null 2>&1
rm shared_manifest.txt >> /dev/null 2>&1

if [ $# -eq 0 ]; then
    add_hosts_prompt
else
    for var in "$@"
    do
        python client.py add "$var"
    done
fi


python client.py log

echo 'Synchronizing Shared Files with Peers'
python client.py sync

# EOF