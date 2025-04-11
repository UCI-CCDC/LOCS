#!/bin/bash

# Check if the user has provided a log file name
if [ -z "$1" ]; then
    echo "Usage: $0 <output_log_file>"
    exit 1
fi

output_log="$1"

# Initialize or clear the output log file
> "$output_log"

# Run tcpdump continuously and log source-destination pairs (only 4-octet IPs)
sudo tcpdump -n -i eth0 -l | \
    awk '{print $3, $5, $8}' | \
    sed -E 's/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+ > ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+ [a-z]+\.[a-z]+:/\1 \2 \3/' | \
    while read src dst; do
        # Append the source-destination pair to the log
        echo "$src $dst" >> "$output_log"
    done