#!/bin/bash

./bin/evpencutil-cli -c list-supported | grep -e "aes" -e "chacha" | grep -v -e "ecb" -e "cfb[0-9]" | sort | while read cipher ; do
	./bin/evpencutil-cli -m list-supported | grep -e "sha512" -e "blake2b512" | sort | while read digest ; do
		./bin/evpencutil-gui -c "$cipher" -m "$digest" "$@" &
		sleep 3s
		kill -TERM $(pgrep -d " " evpencutil-gui)
	done
done
