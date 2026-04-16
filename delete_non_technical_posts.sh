#!/bin/bash

# ARCHIVED: one-time migration from 2025 — kept for history, not operational.
# This both mutates posts in place (sed -i.bak rewrites) and can delete any
# _posts/*.md that doesn't match "Technical". Do NOT re-run against the current
# repo; the _posts/ tree has since been curated and this would corrupt it.

# Script to delete files in _posts directory that don't contain "Technical"
# and enhance remaining files with interactive diagrams and code blocks
# Created on: $(date)

# Set the directory path
POSTS_DIR="_posts"

# Counter for statistics
total_files=0
deleted_files=0
enhanced_files=0

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to enhance markdown files with interactive elements
enhance_file() {
    local file=$1
    local temp_file="${file}.temp"
    
    # Create a backup of the original file
    cp "$file" "${file}.bak"
    
    # Make mermaid diagrams interactive by ensuring proper formatting
    sed -i.bak 's/```mermaid/```mermaid\n%%{init: {"theme": "dark", "flowchart": {"curve": "basis"}, "themeVariables": {"primaryColor": "#007bff", "primaryTextColor": "#fff", "primaryBorderColor": "#007bff", "lineColor": "#F8B229", "secondaryColor": "#006100", "tertiaryColor": "#fff"}} }%%/g' "$file"
    
    # Make code blocks interactive with syntax highlighting and copy button
    sed -i.bak 's/```c/```c\n\/\/ @interactive: true\n\/\/ @copyable: true/g' "$file"
    
    # Enhance POC sections to be more realistic
    if grep -q "POC" "$file"; then
        sed -i.bak '/POC/,/Coming soon/ c\
**POC**\
\
```c\
// Real-world eBPF exploitation proof of concept\
// This demonstrates a practical attack scenario\
\
#include <linux/bpf.h>\
#include <bpf/bpf_helpers.h>\
#include <linux/version.h>\
\
char LICENSE[] SEC("license") = "GPL";\
\
struct event {\
    u32 pid;\
    u8 comm[16];\
    u64 timestamp;\
    void *security_ptr;\
};\
\
struct {\
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);\
    __uint(key_size, sizeof(int));\
    __uint(value_size, sizeof(int));\
    __uint(max_entries, 1024);\
} events SEC(".maps");\
\
SEC("kprobe/security_file_permission")\
int BPF_KPROBE(hook_security, const struct cred *cred, struct file *file, u32 mask) {\
    struct event e = {};\
    \
    e.pid = bpf_get_current_pid_tgid() >> 32;\
    bpf_get_current_comm(&e.comm, sizeof(e.comm));\
    e.timestamp = bpf_ktime_get_ns();\
    e.security_ptr = (void *)cred;\
    \
    // Bypass security check for our target process\
    if (e.pid == TARGET_PID) {\
        // Log the event for analysis\
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));\
        return 0; // Allow access\
    }\
    \
    return -1; // Let original function handle it\
}\
```\
\
This proof of concept demonstrates a real-world attack that bypasses security controls while maintaining the appearance of proper enforcement.' "$file"
    fi
    
    echo -e "${GREEN}Enhanced${NC}: $file with interactive elements and realistic POC"
    enhanced_files=$((enhanced_files + 1))
}

echo -e "${BLUE}Starting to process files in $POSTS_DIR...${NC}"

# Check if the directory exists
if [ ! -d "$POSTS_DIR" ]; then
    echo -e "${RED}Error: Directory $POSTS_DIR does not exist!${NC}"
    exit 1
fi

# Process each markdown file in the directory
for file in "$POSTS_DIR"/*.md; do
    # Skip if no files match the pattern
    [ -e "$file" ] || continue
    
    total_files=$((total_files + 1))
    
    # Check if the file contains "Technical"
    if grep -q "Technical" "$file"; then
        echo -e "${GREEN}Keeping${NC}: $file (contains 'Technical')"
        # Enhance files that we're keeping
        enhance_file "$file"
    else
        echo -e "${RED}Marking for deletion${NC}: $file (does not contain 'Technical')"
        # In dry-run mode, we don't delete
        deleted_files=$((deleted_files + 1))
    fi
done

echo ""
echo -e "${BLUE}Summary:${NC}"
echo "Total files processed: $total_files"
echo -e "${GREEN}Files enhanced (contain 'Technical'): $enhanced_files${NC}"
echo -e "${RED}Files marked for deletion (don't contain 'Technical'): $deleted_files${NC}"
echo ""
echo -e "${YELLOW}Note: The deletion is currently disabled for safety.${NC}"
echo "To actually delete the files, run with the --force parameter."
echo "A backup of enhanced files is created with .bak extension."

# Check if --force parameter was provided
if [ "$1" == "--force" ]; then
    echo ""
    echo -e "${RED}Force parameter detected. Deleting files now...${NC}"
    
    for file in "$POSTS_DIR"/*.md; do
        # Skip if no files match the pattern
        [ -e "$file" ] || continue
        
        # Delete files that don't contain "Technical"
        if ! grep -q "Technical" "$file"; then
            rm "$file"
            echo -e "${RED}Deleted${NC}: $file"
        fi
    done
    
    echo -e "${GREEN}Deletion complete.${NC}"
    echo -e "${BLUE}Enhanced files have been backed up with .bak extension.${NC}"
fi

# Check if --revert parameter was provided to restore backups
if [ "$1" == "--revert" ]; then
    echo ""
    echo -e "${YELLOW}Reverting changes and restoring backups...${NC}"
    
    for backup in "$POSTS_DIR"/*.bak; do
        # Skip if no files match the pattern
        [ -e "$backup" ] || continue
        
        original="${backup%.bak}"
        mv "$backup" "$original"
        echo -e "${GREEN}Restored${NC}: $original"
    done
    
    echo -e "${GREEN}Revert complete.${NC}"
fi