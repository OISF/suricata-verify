#! /bin/sh

if ./src/suricata --build-info | grep -i lua | grep -q lua; then
    exit 0
fi

echo "lua not enabled"
exit 1
