#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Should have 4 DNP3 data match alerts.
n=$(grep "DNP3 Data match" eve.json | wc -l | xargs)
assert_eq 4 "$n" "bad event count"

exit 0
