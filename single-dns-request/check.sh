#! /bin/sh

. ../functions.sh

# One query for suricon.net.
n=$(jq_count output/eve.json 'select(.dns.type == "query") | select(.dns.rrname == "suricon.net")')
assert_eq 1 "$n" "request"

# One answer with rdata of 181.224.138.142.
n=$(jq_count output/eve.json 'select(.dns.type == "answer") | select(.dns.rdata == "181.224.138.142")')
assert_eq 1 "$n" "response"

