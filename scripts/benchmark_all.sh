#!/bin/bash

./bin/evpencutil-cli -c list-supported | sort | while read cipher ; do
	./bin/evpencutil-cli -m list-supported | sort | while read digest ; do
		./bin/evpencutil-cli -c "$cipher" -m "$digest" "$@" &
		sleep 3s
		kill -TERM $(pgrep -d " " evpencutil-gui)
	done
done
