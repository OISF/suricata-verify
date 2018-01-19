#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Check that there are no events.
n=$(cat fast.log | wc -l | xargs)
assert_eq 0 "$n" "no events expected"
