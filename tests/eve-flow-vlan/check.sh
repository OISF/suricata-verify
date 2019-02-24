#!/bin/sh

. ${TOPDIR}/util/functions.sh

n=$(jq_count eve.json 'select(.event_type == "flow" and .vlan == [6])')
assert_eq 1 "$n" "single vlan"

n=$(jq_count eve.json 'select(.event_type == "flow" and .vlan == [1,10])')
assert_eq 1 "$n" "double-tagged vlan"

exit 0
