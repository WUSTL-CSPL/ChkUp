#!/bin/bash

# Check for the correct number of arguments
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <input file> <offset> <hex number> <output file>"
    exit 1
fi

input_file="$1"
offset="$2"
hex_number="$3"
output_file="$4"

# Create a copy of the input file to the output file
cp "$input_file" "$output_file"

# Calculate the length of the hex number
hex_length=${#hex_number}

# Ensure the hex_length is an even number (each byte = 2 hex digits)
if [ $((hex_length % 2)) -ne 0 ]; then
    echo "The hex number must have an even number of digits."
    exit 1
fi

# Convert the hexadecimal number into a binary format
echo -n $hex_number | xxd -r -p | dd of="$output_file" bs=1 seek="$offset" count=$(($hex_length / 2)) conv=notrunc

echo "Modification complete. Output file is $output_file."