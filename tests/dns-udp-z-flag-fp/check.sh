#! /bin/sh

. ../../util/functions.sh

# Check that there are no events.
n=$(cat output/fast.log | wc -l | xargs)
assert_eq 0 "$n" "no events expected"
