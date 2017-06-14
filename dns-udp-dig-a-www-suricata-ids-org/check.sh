#! /bin/sh

. ../functions.sh

n=$(cat output/eve.json | jq -c 'select(.dns.type == "query")' | wc -l)
assert_eq 1 $n

n=$(cat output/eve.json | jq -c 'select(.dns.type == "answer")' | wc -l)
assert_eq 3 $n

n=$(cat output/eve.json | jq -c 'select(.dns.rrtype == "CNAME")' | wc -l)
assert_eq 1 $n

n=$(cat output/eve.json | jq -c 'select(.dns.rrtype == "A")' | wc -l)
assert_eq 3 $n
