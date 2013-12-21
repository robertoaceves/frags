#!/bin/bash

#####################################################
#####################
######
echo "Traditional packets (without fragments)"

OPTS=" -w 10" # Wait 10 secs before close the connection

echo TCP
nc -6 64:ff9b::192.168.1.2 50000 < image_2_test_tcp.jpg

echo UDP
nc $OPTS -6u 64:ff9b::192.168.1.2 50000 < image_2_test_udp.jpg 

echo ICMP
ping6 -c 1 64:ff9b::192.168.1.2 


#####################################################
#####################
######
echo Fragmented packets

echo UDP
./send_fragments.sh pandas_800B 
./send_fragments.sh pandas_1000B 

echo ICMP
ping6 -c1 -s 4000 64:ff9b::192.168.1.2 

echo ...Done.
