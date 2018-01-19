#! /bin/sh

. ${TOPDIR}/util/functions.sh

n=$(jq_count eve.json 'select(.dns.rrtype != "MX")')
assert_eq 0 $n "only expected mx records"

exit 0

