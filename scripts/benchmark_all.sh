#!/bin/bash

./bin/evpencutil-cli -c list-supported | sort | while read cipher ; do
	./bin/evpencutil-cli -m list-supported | sort | while read digest ; do
		./bin/evpencutil-gui -c "$cipher" -m "$digest" "$@"
	done
done
