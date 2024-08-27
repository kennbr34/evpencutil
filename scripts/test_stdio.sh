#!/bin/bash

BINPATH="./bin/evpencutil-cli -w N=1024"


while : ; do
	FILESIZE=$(echo $RANDOM | cut -b -2)
	BUFFERS=$(echo $RANDOM)

	dd if=/dev/urandom of=./testfile bs=1M count=$FILESIZE &> /dev/null
    
	echo $BINPATH -e -i ./testfile -o ./testfile.enc -p password -b file_buffer=${BUFFERS}k
	$BINPATH -e -i ./testfile -o ./testfile.enc -p password -b file_buffer=${BUFFERS}k
    
	echo $BINPATH -d -i ./testfile.enc -o ./testfile.plain -p password
	$BINPATH -d -i ./testfile.enc -o ./testfile.plain -p password
    
	echo cmp ./testfile ./testfile.plain
	cmp ./testfile ./testfile.plain
    
	echo "cat ./testfile.enc | $BINPATH -d -i - -o ./testfile -p password"
	cat ./testfile.enc | $BINPATH -d -i - -o ./testfile -p password
    
	#echo cmp ./testfile ./testfile.plain
	cmp ./testfile ./testfile.plain
    
	echo "$BINPATH -e -i ./testfile -o - -p password -b file_buffer=${BUFFERS}k -c bf-ofb | $BINPATH -e -i - -o - -p password -c aes-256-cbc -b file_buffer=${BUFFERS}k | $BINPATH -e -i - -o ./testfile.enc -p password -b file_buffer=${BUFFERS}k"
	$BINPATH -e -i ./testfile -o - -p password -b file_buffer=${BUFFERS}k | $BINPATH -e -i - -o - -p password  -b file_buffer=${BUFFERS}k | $BINPATH -e -i - -o ./testfile.enc -p password -b file_buffer=${BUFFERS}k
    
	echo "$BINPATH -d -i ./testfile.enc -o - -p password | $BINPATH -d -i - -o - -p password | $BINPATH -d -i - -o ./testfile.plain -p password"
	$BINPATH -d -i ./testfile.enc -o - -p password | $BINPATH -d -i - -o - -p password | $BINPATH -d -i - -o ./testfile.plain -p password
    
	echo cmp ./testfile ./testfile.plain
	cmp ./testfile ./testfile.plain
done
