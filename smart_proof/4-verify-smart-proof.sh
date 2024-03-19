#!/usr/bin/env bash

# Check if the arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <contract_address> <proof_address>"
    exit 1
fi

# Assign arguments to variables
contract_address=$1
proof_address=$2

# Pass the calldata to the sncast command
sncast --profile testnet \
  --wait \
  invoke \
  --contract-address "$contract_address" \
  --function "verify_and_register_fact_from_contract" \
  --calldata "$proof_address"
