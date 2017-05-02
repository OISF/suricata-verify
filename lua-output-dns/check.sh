#! /bin/sh

set -e

if ! grep -q "Query TX 0d4f \[\*\*\] block.dropbox.com \[\*\*\] A \[\*\*\] 10.16.1.11:49697 -> 10.16.1.1:53" output/lua-dns.log; then
    echo "failed to find query for block.dropbox.com"
    exit 1
fi

if ! cat output/lua-dns.log | \
	grep "Response" | \
	grep "client-cf.dropbox.com" | \
	grep "52.85.112.21" > /dev/null;
then
    echo "failed to find response for client-cf.dropbox.com"
    exit 1
fi

if ! cat output/lua-dns.log | \
	grep "Response TX 62b2" | \
	grep "NXDOMAIN" > /dev/null;
then
    echo "failed to find NXDOMAIN error"
    exit 1
fi

if ! cat output/lua-dns.log | grep "SOA" > /dev/null; then
    echo "failed find SOA response record"
    exit 1
fi

exit 0
