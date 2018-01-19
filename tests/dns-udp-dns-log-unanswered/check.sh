#! /bin/sh

n=$(grep Query dns.log | wc -l | xargs)
if [ "$n" -ne 4 ]; then
    echo "expected 4 queries, found $n"
    exit 1
fi

n=$(grep Response dns.log | wc -l | xargs)
if [ "$n" -ne 4 ]; then
    echo "expected 4 responses, found $n"
    exit 1
fi

exit 0
