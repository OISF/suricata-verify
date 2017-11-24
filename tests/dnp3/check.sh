#! /bin/sh

. ../../util/functions.sh

n=$(jq_count output/eve.json 'select(.event_type == "dnp3")')
assert_eq 55 "$n" "bad dnp3 event count"

exit 0

