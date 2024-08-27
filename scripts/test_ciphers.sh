#!/bin/bash

BINPATH='./bin/evpencutil-cli -w N=1024'
COUNT=$(echo $RANDOM | cut -b 1)

cat $1 | while read cipher ; do

	dd if=/dev/urandom of=./testfile bs=1M count=$COUNT &> /dev/null
	$BINPATH -e -i ./testfile -o ./testfile.enc -p password -c "$cipher"
	if [ $? != 0 ] ; then
		#echo ""$cipher" does not work"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	$BINPATH -d -i ./testfile.enc -o ./testfile.plain -p password &> /dev/null
	if [ $? != 0 ] ; then
		echo ""$cipher" does not work"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	cmp ./testfile ./testfile.plain &> /dev/null
	if [ $? != 0 ] ; then
		echo ""$cipher" does not work"
		rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
		continue
	fi

	rm ./testfile ./testfile.enc ./testfile.plain &> /dev/null
done
