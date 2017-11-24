#! /bin/sh

. ../../util/functions.sh

# Should have one fast log entry.
n=$(cat output/fast.log | wc -l | xargs)
assert_eq 1 "$n" "bad fast.log"

# Should have one eve alert.
n=$(jq_count output/eve.json 'select(.event_type == "alert")')
assert_eq 1 "$n" "eve.json alerts"

exit 0
