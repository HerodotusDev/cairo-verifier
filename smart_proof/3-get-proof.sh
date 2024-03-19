#!/usr/bin/env bash

# Check if the arguments are provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <contract_address>"
    exit 1
fi

# Assign arguments to variables
contract_address=$1

# Pass the calldata to the sncast command
sncast --profile testnet \
  --wait \
  call \
  --contract-address "$contract_address" \
  --function "get_proof" \
