#! /usr/bin/env bash

# Check for 1 tls event.
n=$(cat eve.json | jq -c 'select(.event_type == "tls")' | wc -l | xargs)
if test "${n}" -ne 1; then
    echo "expected 1 event, got $n"
    exit 1
fi

exit 0

    
