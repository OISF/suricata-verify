#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Should have one alert sid 1.
n=$(jq_count eve.json 'select(.alert.signature_id == 1)')
assert_eq 1 "$n" "sig id 1"

# Should have one alert sid 2.
n=$(jq_count eve.json 'select(.alert.signature_id == 2)')
assert_eq 1 "$n" "sig id 1"

exit 0
