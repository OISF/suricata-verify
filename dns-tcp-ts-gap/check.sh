#! /bin/sh

. ../functions.sh

# As a request was missing, we should have 2 requests, but 26
# responses, as each request resulted in 12 responses.
log=./output/eve.json

n=$(cat ${log} | \
	jq -c 'select(.event_type == "dns") | select(.dns.type == "query")' | \
	wc -l)
assert_eq 2 $n

n=$(cat ${log} | \
	jq -c 'select(.event_type == "dns") | select(.dns.type == "answer")' | \
	wc -l)
assert_eq 36 $n

exit 0
