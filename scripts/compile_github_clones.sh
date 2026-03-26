#!/bin/bash

spec_folder="/data/asn1_specs"
file_list=()

# Iterate through the directory and subdirectories
while IFS= read -r -d '' file; do
    if [[ $file == *.asn ]]; then
        file_list+=("$file")
    fi
done < <(find "$spec_folder" -type f -name "*.asn" -print0)

generate_binary() {
    output_folder=$1
    include_folder=$2
    file_name=$3

    if [[ $include_folder == *velichkov* ]]; then
        suffix="_velichkov"
    elif [[ $include_folder == *vlm* ]]; then
        suffix="_vlm"
    elif [[ $include_folder == *mouse07410* ]]; then
        suffix="_mouse07410"
    fi

    if ls "${include_folder}${file_name}"/*.c 1> /dev/null 2>&1; then
        echo "gcc -O0 -g -I"${include_folder}${file_name}" -o "${output_folder}/${file_name}${suffix}.bin" "${include_folder}${file_name}"/*.c /data/git/ASN1Analysis/cpp/base.cpp"
        gcc -O0 -g -I"${include_folder}${file_name}" -o "${output_folder}/${file_name}${suffix}.bin" "${include_folder}${file_name}"/*.c /data/git/ASN1Analysis/cpp/base.cpp
        echo "Built ${output_folder}/${file_name}${suffix}.bin"
    else
        echo "No .c files found in ${include_folder}${file_name} folder. Cannot generate binary."
    fi
}q

for file in "${file_list[@]}"; do
    file_name=$(basename "$file")
    generate_binary "/data/jupyter/work" "/data/git/vlm/" "${file_name}"
    generate_binary "/data/jupyter/work" "/data/git/velichkov/" "${file_name}"
    generate_binary "/data/jupyter/work" "/data/git/mouse07410/" "${file_name}"
done