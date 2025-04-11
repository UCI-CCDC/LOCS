#!/bin/sh

# Check if lsof is installed
if ! command -v lsof >/dev/null 2>&1; then
	echo "lsof is not installed. Installing lsof..."

	if [ -x "$(command -v apk)" ]; then
		apk add lsof
	elif [ -x "$(command -v apt-get)" ]; then
		apt-get install -y lsof
	elif [ -x "$(command -v yum)" ]; then
		yum install -y lsof
	else
		echo "could not install lsof, needs to be installed manually"
		exit 1
	fi
fi

lsof -nP 2>/dev/null | grep RAW
