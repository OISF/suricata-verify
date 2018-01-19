#! /bin/sh

. ${TOPDIR}/util/functions.sh

filename=$(cat eve.json | jq -c .fileinfo.filename)
assert_eq '"eicar.com"' "$filename" "bad filename"

exit 0
