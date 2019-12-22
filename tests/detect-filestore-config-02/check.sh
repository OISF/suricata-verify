#!/bin/sh
if ! grep -q "Warning: Rule requires file-store but the output file-store is not enabled." $OUTPUT_DIR/rules_analysis.txt; then
    echo "Pattern not found"
    exit 1
fi
exit 0
