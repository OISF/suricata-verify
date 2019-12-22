#!/bin/sh
if grep  '\[ERRCODE: SC_WARN_ALERT_CONFIG(324)\] - One or more rule(s) depends on the file-store output log which is not enabled. Enable the output "file-store"' $OUTPUT_DIR/stdout; then
    echo "pattern found in stdout"
    exit 1
fi
