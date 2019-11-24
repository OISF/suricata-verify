#! /bin/sh

. ${TOPDIR}/util/functions.sh

# Expect as many DNS metadata items as there are alerts
n_dnsmeta=$(jq_count eve.json 'select(.dns)')
n_alerts=$(jq_count eve.json 'select(.alert)')
assert_eq "${n_alerts}" "${n_dnsmeta}" "dnsmetadata"

