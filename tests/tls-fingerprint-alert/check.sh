#! /usr/bin/env bash

# Check for a single alert.
n=$(cat eve.json | jq -c 'select(.event_type == "alert")' | wc -l | xargs)
if test "${n}" -ne 1; then
    echo "expected 1 event, found ${n}"
    exit 1
fi

exit 0
