#!/bin/sh

checkRam () {
    kb_free=$(free -t --kilo | grep Total: | cut -b 13-23)
    mb_free=$(free -t --mega | grep Total: | cut -b 13-23)
    gb_free=$(free -t --giga | grep Total: | cut -b 13-23)

    case "$1" in 
	    -k) echo $kb_free'Kb Free';;
	    -m) echo $mb_free'Mb Free';;
	    -g) echo $gb_free'Gb Free';;
	    *) echo 'Uknown Option!';;
    esac
}

# Run the test case function
checkRam $1

