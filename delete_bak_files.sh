#!/bin/bash

# Delete all .bak files
echo "Deleting .bak files..."
find _posts -name "*.bak" -type f -delete

echo "All .bak files have been deleted."