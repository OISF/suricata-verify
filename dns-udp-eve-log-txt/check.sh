#! /bin/sh

set -e

txt=$(cat output/eve.json | \
	  jq -c 'select(.dns.type == "answer") | select(.dns.rrtype == "TXT") | .dns.rdata')
test "${txt}" = '"v=spf1 include:_spf.google.com ~all"'


