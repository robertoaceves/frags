#!/bin/bash

DEFAULT_BLOCK_SIZE=1000

[ $# -lt 1 ] && echo "USAGE: $(basename $0) INPUT_FILE [BLOCK_SIZE]" \
			&& echo "		INPUT_FILE: is the file to split into... " \
			&& echo "		BLOCK_SIZE: bytes chunks." \
			&& exit

input="$1"
prefix=$input"_"
block_size=$2

function show_error() {
	echo "ERROR: $1"
	exit
}


[ $# -eq 1 ] && block_size=$DEFAULT_BLOCK_SIZE 
[ ! -f $input ] && show_error "Can not read file: $input"
[[ ! $block_size =~ ^[0-9]+$ ]] && show_error "Block size is not a number: $block_size" 

#echo split -a 4 -b $block_size -d $input $prefix 
	 split -a 4 -b $block_size -d $input $prefix 


