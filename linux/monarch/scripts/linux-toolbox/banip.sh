#!/usr/bin/env bash

# Set up banip

echo "iptables -I INPUT 1 -s $1 -j DROP" > /usr/sbin/banip.sh
echo "iptables -I OUTPUT 1 -d $1 -j DROP" >> /usr/sbin/banip.sh
