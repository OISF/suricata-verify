#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Should have two alerts sid 2221034.
n=$(jq_count eve.json 'select(.alert.signature_id == 2221034)')
assert_eq 2 "$n" "sig id 2221034"

exit 0
