#!/usr/bin/env bash

# Check if the arguments are provided
if [ $# -ne 3 ]; then
    echo "Usage: $0 <profile> <contract_address> <fact_hash>"
    exit 1
fi

# Assign arguments to variables
profile=$1
contract_address=$2
fact_hash=$3

# Pass the calldata to the sncast command
sncast --profile "$profile" \
  --wait \
  call \
  --contract-address "$contract_address" \
  --function "is_valid" \
  --calldata "$fact_hash"
