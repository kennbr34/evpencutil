#!/bin/bash

BUFFER=`echo $(echo $RANDOM | cut -b -4)b`
BUFFER=1m
COUNT=$(echo $RANDOM | cut -b -2)
BINPATH="./bin/evpencutil-cli -w N=1024 -t 1 -b file_buffer=$BUFFER"

echo "Testing with $COUNT kilobytes and $BUFFER buffer"

cat $1 | while read cipher ; do

	#echo "Testing "$cipher""

	dd if=/dev/urandom of=./testfile bs=1K count=$COUNT &> /dev/null
	$BINPATH -e -i ./testfile -o ./testfile.enc -p password -c "$cipher" &> /dev/null
	if [ $? != 0 ] ; then
		echo ""$cipher" failed encryption"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	$BINPATH -d -i ./testfile.enc -o ./testfile.plain -p password
	if [ $? != 0 ] ; then
		echo ""$cipher" failed decryption"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	cmp ./testfile ./testfile.plain
	if [ $? != 0 ] ; then
		echo ""$cipher" failed comparison"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	#echo ""$cipher" works"

	rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
done
