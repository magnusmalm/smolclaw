#!/bin/bash
# Embed workspace template files into a C header using od (POSIX)
# Usage: embed_workspace.sh <workspace_dir> <output_header>

set -e

WORKSPACE_DIR="$1"
OUTPUT="$2"

if [ -z "$WORKSPACE_DIR" ] || [ -z "$OUTPUT" ]; then
    echo "Usage: $0 <workspace_dir> <output_header>"
    exit 1
fi

cat > "$OUTPUT" << 'HEADER'
/* Auto-generated workspace file embeddings. Do not edit. */
#ifndef SC_WORKSPACE_DATA_H
#define SC_WORKSPACE_DATA_H

#include "workspace.h"

HEADER

count=0
file_list=""

if [ -d "$WORKSPACE_DIR" ]; then
    while IFS= read -r -d '' file; do
        relpath="${file#$WORKSPACE_DIR/}"
        varname="ws_file_${count}"

        # Convert to C array using od (POSIX standard)
        echo "static const unsigned char ${varname}[] = {" >> "$OUTPUT"
        od -An -tx1 -v < "$file" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//; s/ /, 0x/g; s/^/  0x/; s/$/, /' >> "$OUTPUT"
        echo "};" >> "$OUTPUT"
        size=$(wc -c < "$file")
        echo "static const unsigned int ${varname}_len = ${size};" >> "$OUTPUT"
        echo "" >> "$OUTPUT"

        file_list="${file_list}    {\"${relpath}\", ${varname}, ${varname}_len},\n"
        count=$((count + 1))
    done < <(find "$WORKSPACE_DIR" -type f -print0 | sort -z)
fi

echo "const sc_workspace_file_t sc_workspace_files[] = {" >> "$OUTPUT"
if [ $count -gt 0 ]; then
    printf "$file_list" >> "$OUTPUT"
fi
echo "    {NULL, NULL, 0}" >> "$OUTPUT"
echo "};" >> "$OUTPUT"
echo "const int sc_workspace_file_count = ${count};" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "#endif /* SC_WORKSPACE_DATA_H */" >> "$OUTPUT"
