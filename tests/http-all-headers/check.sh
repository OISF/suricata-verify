#! /bin/sh

. ${TOPDIR}/util/functions.sh

# 9 request headers (2 rows per header + start and end of list).
n=$(jq '.http.request_headers | length' eve.json)
assert_eq 9 "$n"

# Simplified test: check 1 request header
# Arbitrary decision to check "Host": "www.ethereal.com"
n=$(jq ".http.request_headers[] | select(.name | contains(\"Host\")) | select(.value | contains(\"www.ethereal.com\"))" eve.json)
test -n "$n"

# 9 request headers (2 rows per header).
n=$(jq '.http.response_headers | length ' eve.json)
assert_eq 9 "$n"

# Simplified test: check 1 response header
# Arbitrary decision to check "Content-Length": "18070"
n=$(jq ".http.response_headers[] | select(.name | contains(\"Content-Length\")) | select(.value | contains(\"18070\"))" eve.json)
test -n "$n"
