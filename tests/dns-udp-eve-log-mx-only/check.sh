#! /bin/sh

. ../../util/functions.sh

n=$(jq_count output/eve.json 'select(.dns.rrtype != "MX")')
assert_eq 0 $n "only expected mx records"

exit 0

