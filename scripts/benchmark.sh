#!/bin/bash

TESTFILE=$1
KEYFILE=$2


ENC_GUI="../bin/evpencutil-gui -q -e -B -i $TESTFILE -o ${TESTFILE}.enc -k $KEYFILE"
DEC_GUI="../bin/evpencutil-gui -q -d -B -i ${TESTFILE}.enc -o ${TESTFILE}.plain -k $KEYFILE"

echo_do() {
    echo -e "\t$@"
    bash -c "$@"
}

do_test() {
    
    echo_do "$ENC_GUI $@"
    echo_do "$DEC_GUI $@"
    echo ""
}

#AES Testing
#SHA256 Testing
echo "Testing with AES-256-CTR and SHA256 with default buffers"
do_test "-c aes-256-ctr -m sha256"

echo "Testing with AES-256-CTR and SHA256 with 16m buffers"
do_test "-c aes-256-ctr -m sha256 -b auth_buffer=16m,file_buffer=16m"

echo "Testing with AES-256-CTR and SHA256 with 32m buffers"
do_test "-c aes-256-ctr -m sha256 -b auth_buffer=32m,file_buffer=32m"

echo "Testing with AES-256-CTR and SHA256 with 64m buffers"
do_test "-c aes-256-ctr -m sha256 -b auth_buffer=64m,file_buffer=64m"

echo "Testing with AES-256-CTR and SHA256 with 256m buffers"
do_test "-c aes-256-ctr -m sha256 -b auth_buffer=256m,file_buffer=256m"

echo "Testing with AES-256-CTR and SHA256 with 512m buffers"
do_test "-c aes-256-ctr -m sha256 -b auth_buffer=512m,file_buffer=512m"

echo "Testing with AES-256-CTR and SHA256 with 1024m buffers"
do_test "-c aes-256-ctr -m sha256 -b auth_buffer=1024m,file_buffer=1024m"

#With only file buffers differing
echo "Testing with AES-256-CTR and SHA256 with 16m buffers"
do_test "-c aes-256-ctr -m sha256 -b file_buffer=16m"

echo "Testing with AES-256-CTR and SHA256 with 32m buffers"
do_test "-c aes-256-ctr -m sha256 -b file_buffer=32m"

echo "Testing with AES-256-CTR and SHA256 with 64m buffers"
do_test "-c aes-256-ctr -m sha256 -b file_buffer=64m"

echo "Testing with AES-256-CTR and SHA256 with 256m buffers"
do_test "-c aes-256-ctr -m sha256 -b file_buffer=256m"

echo "Testing with AES-256-CTR and SHA256 with 512m buffers"
do_test "-c aes-256-ctr -m sha256 -b file_buffer=512m"

echo "Testing with AES-256-CTR and SHA256 with 1024m buffers"
do_test "-c aes-256-ctr -m sha256 -b file_buffer=1024m"

#SHA512 Testng
echo "Testing with AES-256-CTR and SHA512 with default buffers"
do_test "-c aes-256-ctr -m sha512"

echo "Testing with AES-256-CTR and SHA512 with 16m buffers"
do_test "-c aes-256-ctr -m sha512 -b auth_buffer=16m,file_buffer=16m"

echo "Testing with AES-256-CTR and SHA512 with 32m buffers"
do_test "-c aes-256-ctr -m sha512 -b auth_buffer=32m,file_buffer=32m"

echo "Testing with AES-256-CTR and SHA512 with 64m buffers"
do_test "-c aes-256-ctr -m sha512 -b auth_buffer=64m,file_buffer=64m"

echo "Testing with AES-256-CTR and SHA512 with 512m buffers"
do_test "-c aes-256-ctr -m sha512 -b auth_buffer=512m,file_buffer=512m"

echo "Testing with AES-256-CTR and SHA512 with 1024m buffers"
do_test "-c aes-256-ctr -m sha512 -b auth_buffer=1024m,file_buffer=1024m"

#With only file buffers differing
echo "Testing with AES-256-CTR and SHA512 with 16m buffers"
do_test "-c aes-256-ctr -m sha512 -b file_buffer=16m"

echo "Testing with AES-256-CTR and SHA512 with 32m buffers"
do_test "-c aes-256-ctr -m sha512 -b file_buffer=32m"

echo "Testing with AES-256-CTR and SHA512 with 64m buffers"
do_test "-c aes-256-ctr -m sha512 -b file_buffer=64m"

echo "Testing with AES-256-CTR and SHA512 with 512m buffers"
do_test "-c aes-256-ctr -m sha512 -b file_buffer=512m"

echo "Testing with AES-256-CTR and SHA512 with 1024m buffers"
do_test "-c aes-256-ctr -m sha512 -b file_buffer=1024m"

#ChaCha20 Testng
#SHA256 Testing
echo "Testing with ChaCha20 and SHA256 with default buffers"
do_test "-c chacha20 -m sha256"

echo "Testing with ChaCha20 and SHA256 with 16m buffers"
do_test "-c chacha20 -m sha256 -b auth_buffer=16m,file_buffer=16m"

echo "Testing with ChaCha20 and SHA256 with 32m buffers"
do_test "-c chacha20 -m sha256 -b auth_buffer=32m,file_buffer=32m"

echo "Testing with ChaCha20 and SHA256 with 64m buffers"
do_test "-c chacha20 -m sha256 -b auth_buffer=64m,file_buffer=64m"

echo "Testing with ChaCha20 and SHA256 with 256m buffers"
do_test "-c chacha20 -m sha256 -b auth_buffer=256m,file_buffer=256m"

echo "Testing with ChaCha20 and SHA256 with 512m buffers"
do_test "-c chacha20 -m sha256 -b auth_buffer=512m,file_buffer=512m"

echo "Testing with ChaCha20 and SHA256 with 1024m buffers"
do_test "-c chacha20 -m sha256 -b auth_buffer=1024m,file_buffer=1024m"

#With only file buffers differing
echo "Testing with ChaCha20 and SHA256 with 16m buffers"
do_test "-c chacha20 -m sha256 -b file_buffer=16m"

echo "Testing with ChaCha20 and SHA256 with 32m buffers"
do_test "-c chacha20 -m sha256 -b file_buffer=32m"

echo "Testing with ChaCha20 and SHA256 with 64m buffers"
do_test "-c chacha20 -m sha256 -b file_buffer=64m"

echo "Testing with ChaCha20 and SHA256 with 256m buffers"
do_test "-c chacha20 -m sha256 -b file_buffer=256m"

echo "Testing with ChaCha20 and SHA256 with 512m buffers"
do_test "-c chacha20 -m sha256 -b file_buffer=512m"

echo "Testing with ChaCha20 and SHA256 with 1024m buffers"
do_test "-c chacha20 -m sha256 -b file_buffer=1024m"

#SHA512 Testng
echo "Testing with ChaCha20 and SHA512 with default buffers"
do_test "-c chacha20 -m sha512"

echo "Testing with ChaCha20 and SHA512 with 16m buffers"
do_test "-c chacha20 -m sha512 -b auth_buffer=16m,file_buffer=16m"

echo "Testing with ChaCha20 and SHA512 with 32m buffers"
do_test "-c chacha20 -m sha512 -b auth_buffer=32m,file_buffer=32m"

echo "Testing with ChaCha20 and SHA512 with 64m buffers"
do_test "-c chacha20 -m sha512 -b auth_buffer=64m,file_buffer=64m"

echo "Testing with ChaCha20 and SHA512 with 512m buffers"
do_test "-c chacha20 -m sha512 -b auth_buffer=512m,file_buffer=512m"

echo "Testing with ChaCha20 and SHA512 with 1024m buffers"
do_test "-c chacha20 -m sha512 -b auth_buffer=1024m,file_buffer=1024m"

#With only file buffers differing
echo "Testing with ChaCha20 and SHA512 with 16m buffers"
do_test "-c chacha20 -m sha512 -b file_buffer=16m"

echo "Testing with ChaCha20 and SHA512 with 32m buffers"
do_test "-c chacha20 -m sha512 -b file_buffer=32m"

echo "Testing with ChaCha20 and SHA512 with 64m buffers"
do_test "-c chacha20 -m sha512 -b file_buffer=64m"

echo "Testing with ChaCha20 and SHA512 with 512m buffers"
do_test "-c chacha20 -m sha512 -b file_buffer=512m"

echo "Testing with ChaCha20 and SHA512 with 1024m buffers"
do_test "-c chacha20 -m sha512 -b file_buffer=1024m"

