#!/bin/bash

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <docker container port>"
	exit 1
fi

docker cp $1:/workspaces/package/bin/api .
