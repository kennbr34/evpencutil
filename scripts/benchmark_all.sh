#!/bin/bash

cat $1 | while read cipher ; do
	cat $2 | while read digest ; do
		cat /dev/zero | ./bin/evpencutil-gui -q -B -a 5 -e -i - -o /dev/null -p password -c $cipher -m $digest -w N=1024
	done
done
