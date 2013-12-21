
echo "TODO: Set CHECKSUM VALUES for all the packets"
echo "TODO: Define PAYLOAD transmission"

#########################
############
###### Connection termination

A=10

# 6 >4: SYN packet
./frags -6tk --da6=64:ff9b::192.168.1.2 --sa6=c0ca:db8:2001:2::2 --sp=50000 --dp=50000 --flag-syn --seq=$A --tcp-chksum=0466

# 4 >6: SYN-ACK packet
B=20
./frags -4tk --da4=192.168.1.2 sa4=192.168.1.2 --sp=50000 --dp=50000 --flag-syn --flag-ack --ack=$((A+1)) --seq=$B --tcp-chksum=1234

# 6 >4: ACK packet
./frags -6tk --da6=64:ff9b::192.168.1.2 -sa6=c0ca:db8:2001:2::2 --sp=50000 --dp=50000 --flag-ack --seq=$((A+1) --ack=$((B+1)) --tcp-chksum=1234

#########################
############
###### Payload Transmission

#Try sending an unfragment packet
#./frags -f $dir/$file -k -6$PROTO --sa6=$ADDR_SRC --da6=$ADDR_DST --dp=$PORT_DST --seq=$A --frag-off=$offset -tcp-chksum=$CHECKSUM


#########################
############
###### Connection termination

# DEBEMOS INCREMENTAR EL NUMERO DE SECUENCIA?

A=$((A+1))
B=$((B+1))
# 6 >4: FIN packet

./frags -6tk --da6=64:ff9b::192.168.1.2 -sa6=c0ca:db8:2001:2::2 --sp=50000 --dp=50000 --flag-fin --seq=$A --tcp-chksum=1234

# 4 >6: FIN-ACK packet
./frags -4tk --da4=192.168.1.2 sa4=192.168.1.2 --sp=50000 --dp=50000 --flag-fin --flag-ack --ack=$((A+1)) --seq=$B --tcp-chksum=1234

# 6 >4: FIN packet

./frags -6tk --da6=64:ff9b::192.168.1.2 -sa6=c0ca:db8:2001:2::2 --sp=50000 --dp=50000 --flag-ack --seq=$((A+1) --ack=$((B+1)) --tcp-chksum=1234

