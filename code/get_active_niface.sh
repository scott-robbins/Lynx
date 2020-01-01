#!/bin/sh
ifconfig | grep BROADCAST | grep RUNNING | cut -d ':' -f 1
#EOF