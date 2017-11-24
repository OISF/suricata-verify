#! /bin/sh

# Check queries.
c=$(cat output/eve.json | jq -c 'select(.dns.type == "query")' | wc -l | xargs)
if [ "${c}" -ne 2 ]; then
    echo "error: expected 2 DNS queries, got ${c}"
    exit 1
fi

# Check answer count.
c=$(cat output/eve.json | jq -c 'select(.dns.type == "answer")' | wc -l | xargs)
if [ "${c}" -ne 9 ]; then
    echo "error: expected 9 DNS answers, got ${c}"
    exit 1
fi
