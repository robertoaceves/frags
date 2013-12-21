#!/bin/bash

FRAGS="../usr/frags"
IP_VERSION=6 # Valid values: 4 or 6
PROTO=u
if [ $IP_VERSION == 6 ]
then
	ADDR_SRC="c0ca:db8:2001:2::2"
	ADDR_DST="64:ff9b::192.168.1.2"
	CHECKSUM=3b11
else
	ADDR_SRC="192.168.1.2"
	ADDR_DST="192.168.2.1"
	CHECKSUM=0601
fi
PORT_DST=50000
FRAG_ID=01234

[ $# -ne 1 ] && echo "Sends all files contained in a directory." && \
				echo "Filenames are sorted numerically." && \
				echo "" && \
				echo "USAGE: $(basename $0) DIR" && \
				echo "	DIR: where the files to send are." && exit
dir="$1"
dir=${dir%%/}
[ ! -d $dir ] && echo "Cannot read directory: $dir" && exit

cont=0
offset=0
files=( $(ls -v $dir) )
total_size=$(stat -c %s $dir/* | awk 'BEGIN{sum=0} {sum+=$1} END{print sum}')
total_size=$((total_size+8)) # Add the UDP header size

# Get the file size from the first file.
filesize=$(stat -c %s "$dir/${files[0]}")
for file in ${files[@]}
do
	filenumber=$(echo $file | sed -e 's/.*_//' -e 's/[0]\+//')
	offset=$((filesize * filenumber))
	[ $offset != 0 ] && offset=$((offset + 8))  # Add the UDP header size


	CMD="sudo $FRAGS -f $dir/$file -k"
       	if [ $IP_VERSION == 4 ]; then
		CMD+=" -4$PROTO"
		CMD+=" --sa4=$ADDR_SRC --da4=$ADDR_DST"
	else
		CMD+=" -6$PROTO"
		CMD+=" --sa6=$ADDR_SRC --da6=$ADDR_DST"
		CMD+=" --inc-frag-hdr"
	fi
	CMD+=" --frag-id=$FRAG_ID"
	if [ $PROTO == i ]; then 
		CMD+=" --id=$PORT_DST"
	else
		CMD+=" --dp=$PORT_DST"
	fi
	CMD+=" --frag-off=$offset"

	if [ $offset == 0 ]
	then
		#echo "-- primera parte"
		CMD+=" --udp-chksum=$CHECKSUM -M --udp-len=$total_size"
		offset=$((offset+8))
	elif [ $cont != $((${#files[@]}-1)) ]
	then
		#echo "-- parte intermedia"
		CMD+=" -M"
	else
		#echo "-- ultima parte"
		echo
	fi

	CMD=${CMD[@]}

	#echo $CMD
	     $CMD

	cont=$((++cont))
done

