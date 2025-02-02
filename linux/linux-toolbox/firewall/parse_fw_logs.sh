#!/bin/bash

# ---------------------------------------------------
# Script Name: parse_logs.sh
# Description: Parses a log file to extract Log Prefix,
#              Source IP, Source Port, Destination IP, and Destination Port
#              and writes unique lines to an output file with aligned columns,
#              ignoring Source Port and entries with port numbers above 20000
#              when determining uniqueness.
# Usage: ./parse_logs.sh /path/to/input.log /path/to/output.txt
# ---------------------------------------------------

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display usage information
usage() {
    echo "Usage: $0 /path/to/input.log /path/to/output.txt"
    exit 1
}

# Check if exactly two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Error: Invalid number of arguments."
    usage
fi

# Assign input and output file paths from arguments
INPUT_FILE="$1"
OUTPUT_FILE="$2"

# Check if input file exists and is readable
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist."
    exit 1
fi

if [ ! -r "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' is not readable."
    exit 1
fi

# Initialize the output file with a header
printf "%-15s %-15s %-10s %-15s %-10s\n" "Log_Prefix" "Source_IP" "Src_Port" "Destination_IP" "Dst_Port" > "$OUTPUT_FILE"

# Use awk to parse each line and extract the required fields, ensuring unique lines (ignoring Source Port and high ports for uniqueness)
awk '
{
    # Initialize variables for each line
    prefix = "";
    src = "";
    dst = "";
    spt = "";
    dpt = "";
    
    # Extract the log prefix (text within square brackets)
    match($0, /\[([^]]+)\]/, arr);
    if (arr[1] != "") {
        prefix = arr[1];
    }
    
    # Iterate through each field in the line
    for (i = 1; i <= NF; i++) {
        # Extract Source IP
        if ($i ~ /^SRC=/) {
            split($i, a, "=");
            src = a[2];
        }
        # Extract Destination IP
        if ($i ~ /^DST=/) {
            split($i, a, "=");
            dst = a[2];
        }
        # Extract Source Port
        if ($i ~ /^SPT=/) {
            split($i, a, "=");
            spt = a[2];
        }
        # Extract Destination Port
        if ($i ~ /^DPT=/) {
            split($i, a, "=");
            dpt = a[2];
        }
    }
    
    # Construct a unique key for each line, ignoring Source Port and high-numbered ports for uniqueness
    if (prefix != "" && src != "" && dst != "" && dpt != "" && dpt <= 20000) {
        unique_key = sprintf("%s %s %s %s", prefix, src, dst, dpt);
        line = sprintf("%-15s %-15s %-10s %-15s %-10s", prefix, src, spt, dst, dpt);
        if (!seen[unique_key]++) {
            print line;
        }
    }
}
' "$INPUT_FILE" >> "$OUTPUT_FILE"

echo "Parsing complete. Unique extracted data written to '$OUTPUT_FILE'."

