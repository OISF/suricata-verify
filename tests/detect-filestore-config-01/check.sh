#!/bin/sh
if  grep -q "Warning: Rule requires file-store but the output file-store is not enabled." $OUTPUT_DIR/rules_analysis.txt; then
    echo "Pattern found in rules_analysis.txt"
    exit 1
fi
