#! /bin/sh

# Expect 9 dns records.
n=$(cat output/dns.json | jq -c 'select(.event_type == "dns")' | wc -l)
if test $n -ne 9; then
    echo "failed: expected 9 dns events, got $n"
    exit 1
fi

# 4 are queries.
n=$(cat output/dns.json | jq -c 'select(.event_type == "dns") | select(.dns.type == "query")' | wc -l)
if test $n -ne 4; then
    echo "failed: expected 4 dns queries, got $n"
    exit 1
fi

# 4 are queries.
n=$(cat output/dns.json | jq -c 'select(.event_type == "dns") | select(.dns.type == "answer")' | wc -l)
if test $n -ne 5; then
    echo "failed: expected 5 dns answers, got $n"
    exit 1
fi
