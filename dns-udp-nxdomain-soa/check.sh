#! /bin/sh

. ../functions.sh

# Look for 2 responses with rcode == "NXDOMAIN".
n=$(jq_count output/eve.json 'select(.dns.rcode == "NXDOMAIN")')
assert_eq 2 "$n" "nxdomain responses"

exit 0
