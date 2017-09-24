#! /bin/sh

count=$(cat output/eve.json | jq -c 'select(.dns.type=="query")' | wc -l | xargs)
if [ "${count}" -ne 20 ]; then
    echo "error: expected 20 queries, got ${count}"
    exit 1
fi

count=$(cat output/eve.json | jq -c 'select(.dns.type=="answer")' | wc -l | xargs)
if [ "${count}" -ne 40 ]; then
    echo "error: expected 40 answers, got ${count}"
    exit 1
fi

exit 0
