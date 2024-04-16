#!/usr/bin/env bash

# Check if the arguments are provided
if [ $# -ne 3 ]; then
    echo "Usage: $0 <profile> <contract_address> <calldata_file>"
    exit 1
fi

# Assign arguments to variables
profile=$1
contract_address=$2
calldata_file=$3

# Check if the file exists
if [ ! -f "$calldata_file" ]; then
    echo "Error: File '$calldata_file' not found."
    exit 1
fi

# Read calldata from the specified file
calldata=$(<$calldata_file)

# Pass the calldata to the sncast command
sncast --profile "$profile" \
  --wait \
  invoke \
  --contract-address "$contract_address" \
  --function "verify_and_register_fact" \
  --calldata $calldata
