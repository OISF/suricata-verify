#! /bin/sh

. ../../util/functions.sh

# One DNS request.
n=$(jq_count output/eve.json 'select(.event_type == "dns") | select(.dns.type == "query")')
assert_eq 1 $n "dns requests"

# 12 DNS responses.
n=$(jq_count output/eve.json 'select(.event_type == "dns") | select(.dns.type == "answer")')
assert_eq 12 $n "dns responses"
