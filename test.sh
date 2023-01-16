#!/bin/bash

TESTFILE=$1
KEYFILE=$2


ENC_CLI="./evpencutil-cli -e -i $TESTFILE -o ${TESTFILE}.enc"
DEC_CLI="./evpencutil-cli -d -i ${TESTFILE}.enc -o ${TESTFILE}.plain"

ENC_GUI="./evpencutil-gui -q -e -i $TESTFILE -o ${TESTFILE}.enc"
DEC_GUI="./evpencutil-gui -q -d -i ${TESTFILE}.enc -o ${TESTFILE}.plain"

CMP_RES="cmp ${TESTFILE} ${TESTFILE}.plain"

echo_do() {
    echo -e "\t$@"
    bash -c "$@"
}

do_test() {
    echo_do "$ENC_CLI $@"
    echo_do "$DEC_CLI $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_GUI $@"
    echo_do "$DEC_GUI $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_GUI $@"
    echo_do "$DEC_CLI $@"
    bash -c "$CMP_RES"
    echo ""
    
    echo_do "$ENC_CLI $@"
    echo_do "$DEC_GUI $@"
    bash -c "$CMP_RES"
    echo ""
}
echo "Testing with password and default paramaters"
do_test "-p password"

echo "Testing with password and non-default scrypt work factors"
do_test "-p password -w N=1024"

echo "Testing with password and non-default scrypt work factors, and non-default buffers"
do_test "-p password -w N=1024 -s mac_buffer=64m,message_buffer=64m"

echo "Testing with keyfile with default parameters"
do_test "-k $KEYFILE"

echo "Testing with keyfile and password with default parameters"
do_test "-k $KEYFILE -p password"

echo "Testing with keyfile and password with non-default scrypt work factors and non-default buffers"
do_test "-k $KEYFILE -p password -w N=1024 -s mac_buffer=64m,message_buffer=64m"
