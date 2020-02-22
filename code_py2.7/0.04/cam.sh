#!/bin/sh

for i in {1..1000};
do
    echo 'Snapping Image #'$i
    rm im.jpeg
    raspistill -t 1 -o im.jpeg;
    sshpass -p '$1' sftp root@192.236.160.95:/home/Lynx/code_py2.7/0.04/SHARED/  <<< $'put im.jpeg'
    sleep 35
done;

#EOF