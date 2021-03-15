#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Should be no answers.
n=$(jq_count eve.json 'select(.event_type == "dns") | select(.dns.type != "query")')
assert_eq 0 $n "only queries expected"

exit 0

