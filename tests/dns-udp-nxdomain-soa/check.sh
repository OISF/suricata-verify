#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Look for 2 responses with rcode == "NXDOMAIN".
n=$(jq_count eve.json 'select(.dns.rcode == "NXDOMAIN")')
assert_eq 2 "$n" "nxdomain responses"

exit 0
