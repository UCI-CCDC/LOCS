#!/bin/bash
usage() {
    echo 'Usage: carto.sh <nmap_cidr> <internal_prefix>'
    echo 'Example: carto.sh 10.100.100.0/24 192.168.220.'
    exit 1
}

if [ ! -f ./cartographerl ]
then
    echo "No cartographer binary detected!"
    echo "Please run this in the directory where you've downloaded cartographer."
    exit 1
fi

if [ -z "$1" ] || [ -z "$2" ]
then
    usage
fi

cidr="$1"
internal_prefix="$2"

./cartographerl "$cidr" "$internal_prefix"
