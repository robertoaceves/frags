#!/bin/bash
for i in {0..65535}
do
	sudo /home/nat64/Desktop/frags/usr/frags -6 --sa6 c0ca:db8:2001:2::2 --da6 64:ff9b::192.168.1.2 -u --sp $i --dp 5000 --udp-len=13 --udp-chksum e61c
	echo 
done

for i in {0..2}
do
	sudo /home/nat64/Desktop/frags/usr/frags -6 --sa6 c0ca:db8:2001:2::3 --da6 64:ff9b::192.168.1.2 -u --sp $i --dp 5000 --udp-len=13 --udp-chksum e61c
done

