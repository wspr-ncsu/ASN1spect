#!/bin/bash

#DIRECTORY="/data/git/wireshark/epan/dissectors/asn1"
DIRECTORY="/data/asn1_specs"

# Execute the grep command and process the output
# Array to hold class names
declare -a classnames

# Find and extract class names
while IFS=: read -r filepath line; do
  # Skip lines that start with '--' (comments)
  if [[ "$line" =~ ^\s*-- ]]; then
    continue
  fi
  # Extract the part before ::= CLASS
  classname=$(echo "$line" | sed 's/^\s*\(.*\)\s*::=.*$/\1/' | sed 's/[[:space:]]*$//')
  # Add the class name to the arra
  classnames+=("$classname")

done < <(find $DIRECTORY -name "*.asn" -exec grep "::= ENUMERATED" {} +)

classnames=($(for classname in "${classnames[@]}"; do echo "${classname}"; done | sort -u))

for classname in "${classnames[@]}"; do
	echo $classname
done
