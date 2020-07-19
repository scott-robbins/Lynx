#!/bin/bash


function getfilename(){
    if [[ $# -ne 1 ]]; then 
    	echo 'Incorrect Usage!'
	exit
    else
        IFS='FOR'
	name='$1'
        read -ra NAME <<< "$name"
	FILENAME=$(echo $NAME | cut -d '/' -f 3)	
    fi

}




if [[ $# -ne 1 ]]; then 
	echo 'Incorrect Usage!'
else
    if [[ $1 -eq 'all' ]]; then 
        echo 'Reading ALL Messages';
    else
	python client.py -read_from $1;
    fi

fi


#EOF
