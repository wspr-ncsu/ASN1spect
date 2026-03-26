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

done < <(find $DIRECTORY -name "*.asn" -exec grep "::= CLASS" {} +)

classnames=($(for classname in "${classnames[@]}"; do echo "${classname}"; done | sort -u))

# Search each file for definitions that use the class names
for classname in "${classnames[@]}"; do
#  echo "Searching for definitions using class: $classname"
  while IFS=: read -r filepath line_number line; do
    if [[ "$line" =~ ^\s*-- ]]; then
      continue
    fi

    # Skip lines that define a class. note: if a new class is defined using this class, it shouldn't be a problem because all classes are collected in the previous grep search.
    if echo "$line" | grep -q "::=\s*CLASS"; then
      continue
    fi
    # Remove everything after the second space character
    modified_line=$(echo "$line" | awk '{print $1, $2}')

    # Print the modified line
    echo "$filepath:$line_number: $modified_line"

  done < <(find $DIRECTORY -name "*.asn" -exec grep -r -n -E "\s$classname\s*::=" {} +)
done
