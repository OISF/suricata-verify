#! /bin/sh

. ${TOPDIR}/util/functions.sh

# 4 queries.
n=$(jq_count eve.json 'select(.dns.type == "query")')
assert_eq 4 "$n" "queries"

# 5 answers.
n=$(jq_count eve.json 'select(.dns.type == "answer")')
assert_eq 5 "$n" "answers"
