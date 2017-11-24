#! /bin/sh

. ../../util/functions.sh

# Should be no answers.
n=$(jq_count output/eve.json 'select(.event_type == "dns") | select(.dns.type != "answer")')
assert_eq 0 $n "only answers expected"

exit 0

