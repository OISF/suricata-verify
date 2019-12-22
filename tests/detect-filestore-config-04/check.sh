#!/bin/sh
if ! grep  -q 'One or more rule(s) depends on the file-store output log which is not enabled. Enable the output "file-store"' $OUTPUT_DIR/stdout; then
    echo "pattern not found"
    exit 1
fi
exit 0
