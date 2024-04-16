#!/usr/bin/env bash

# Check if the arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <profile> <class-hash>"
    exit 1
fi

# Assign arguments to variables
profile=$1
class_hash=$2

# Pass the class hash to the sncast command
sncast --profile "$profile" --wait deploy --class-hash "$class_hash"
