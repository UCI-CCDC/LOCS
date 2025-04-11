#!/bin/bash

# Check if the user has provided a log file name
if [ -z "$1" ]; then
    echo "Usage: $0 <output_log_file>"
    exit 1
fi

output_log="$1"

# Check if the log file exists
if [ ! -f "$output_log" ]; then
    echo "Error: File $output_log does not exist."
    exit 1
fi

# Process the log file to group source IPs and their visited destinations
awk '{print $1, $2}' "$output_log" | \
    sort | \
    uniq -c | \
    awk '{print $2 ": " $3 " visited " $1 " times"}' | \
    sort -k1,1 -k2,2 > "organized.log"

awk '{print $3}' "$output_log" | \
    sort | \
    uniq -c | \
    awk '{print $2 " visited " $1 " times"}' | grep "\." > "dns.log"
cat organized.log
cat dns.log | grep '\.'