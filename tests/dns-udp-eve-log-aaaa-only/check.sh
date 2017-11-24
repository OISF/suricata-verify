#! /bin/sh

. ../../util/functions.sh

n=$(jq_count output/eve.json 'select(.dns.rrtype == "AAAA")')
assert_eq 2 $n "expected 2 aaaa records"

n=$(jq_count output/eve.json 'select(.dns.rrtype != "AAAA")')
assert_eq 0 $n "expected 0 non-aaaa records"

exit 0

