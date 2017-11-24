#! /bin/sh

. ../../util/functions.sh

filename=$(cat output/eve.json | jq -c .fileinfo.filename)
assert_eq '"eicar.com"' "$filename" "bad filename"

exit 0
