#! /bin/sh

. ${TOPDIR}/util/functions.sh

n=$(jq_count eve.json 'select(.dns.rrtype == "AAAA")')
assert_eq 2 $n "expected 2 aaaa records"

n=$(jq_count eve.json 'select(.dns.rrtype != "AAAA")')
assert_eq 0 $n "expected 0 non-aaaa records"

exit 0

