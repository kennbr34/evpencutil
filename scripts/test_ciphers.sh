#!/bin/bash

BUFFER=`echo $(echo $RANDOM)b`
COUNT=$(echo $RANDOM)
BINPATH="./bin/evpencutil-cli -w N=1024"

echo "Testing with $COUNT bytes and default buffer"

cat $1 | while read cipher ; do

	#echo "Testing "$cipher""

	dd if=/dev/urandom of=./testfile bs=1 count=$COUNT &> /dev/null
	$BINPATH -e -i ./testfile -o ./testfile.enc -p password -c "$cipher" &> /dev/null
	if [ $? != 0 ] ; then
		#echo ""$cipher" failed encryption"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	$BINPATH -d -i ./testfile.enc -o ./testfile.plain -p password &> /dev/null
	if [ $? != 0 ] ; then
		echo ""$cipher" failed decryption"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		#continue
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
