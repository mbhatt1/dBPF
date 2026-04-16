#!/bin/bash

# ARCHIVED: one-time migration from 2025 — kept for history, not operational.
# Do not run; the .bak files this targeted no longer exist in _posts/.

# Delete all .bak files
echo "Deleting .bak files..."
find _posts -name "*.bak" -type f -delete

echo "All .bak files have been deleted."