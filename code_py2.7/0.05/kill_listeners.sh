#!/bin/bash
ps a | grep engine.py | cut -b -6 | while read n;
do
    kill -9 $n
done
#EOF