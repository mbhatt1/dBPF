#!/bin/bash
set -euo pipefail

# Delete all .bak files
echo "Deleting .bak files..."
find _posts -name "*.bak" -type f -delete

# Generate table of contents
echo "Generating table of contents..."

# Create a temporary file for the TOC
TOC_FILE="index.md"
TOC_TEMP="toc_temp.md"

# Extract the header from the existing index.md file
if [ -f "$TOC_FILE" ]; then
    # Extract everything before the "## Table of Contents" line
    sed -n '1,/^## Table of Contents/p' "$TOC_FILE" > "$TOC_TEMP"
else
    # Create a default header if index.md doesn't exist
    cat > "$TOC_TEMP" << EOF
---
layout: default
title: eBPF Field Manual
---

# eBPF Field Manual: Diabolical Edition

A comprehensive guide to eBPF exploitation techniques and their mitigations.

## Table of Contents
EOF
fi

# Add the automatically generated TOC
echo "" >> "$TOC_TEMP"

# Process each post file
for post in $(find _posts -name "*.md" | sort); do
    # Extract the date and title from the filename and frontmatter
    filename=$(basename "$post")
    date=${filename:0:10}
    
    # Extract the title from the frontmatter
    title=$(grep -m 1 "^title:" "$post" | sed 's/title: *"\(.*\)"/\1/' | sed 's/title: *\(.*\)/\1/')
    
    # Extract the first heading as a fallback if title is not found in frontmatter
    if [ -z "$title" ]; then
        title=$(grep -m 1 "^# " "$post" | sed 's/# \(.*\)/\1/')
    fi
    
    # Format the date
    formatted_date=$(date -d "$date" "+%B %d, %Y" 2>/dev/null || echo "$date")
    
    # Create the link
    echo "- [$title]($post) - $formatted_date" >> "$TOC_TEMP"
done

# Add a note about auto-generation
echo "" >> "$TOC_TEMP"
echo "*This table of contents is automatically generated from the posts in the _posts directory.*" >> "$TOC_TEMP"

# If there was content after the TOC in the original file, preserve it
if [ -f "$TOC_FILE" ]; then
    # Extract everything after the "## Table of Contents" line
    sed -n '/^## Table of Contents/,$p' "$TOC_FILE" | tail -n +2 >> "$TOC_TEMP"
fi

# Replace the original file with the new one
mv "$TOC_TEMP" "$TOC_FILE"

echo "Table of contents generated successfully in $TOC_FILE"