#!/bin/bash

#Run test.sh on various sizes of testfiles and key files. Add your own different sizes as necessary.

#Test a 1 megabyte file with a 1 megabyte key file

dd if=/dev/urandom of=./testfile bs=1M count=1
dd if=/dev/urandom of=./keyfile bs=1M count=1

./test.sh ./testfile ./keyfile

#Test a 1 gigabyte file with a 1 megabyte keyfile

dd if=/dev/urandom of=./testfile bs=1M count=1024
dd if=/dev/urandom of=./keyfile bs=1M count=1

./test.sh ./testfile ./keyfile
