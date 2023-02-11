#!/bin/bash

#Run benchmark.sh on various sizes of testfiles and keyfles

echo "Running benchmark on a 1 GB testfile and 1 GB keyfile"
dd if=/dev/urandom of=./testfile bs=1M count=1024
dd if=/dev/urandom of=./keyfile bs=1M count=1024

./benchmark.sh ./testfile ./keyfile

#Clean up

rm ./testfile* ./keyfile
