#!/bin/bash
  
set -x

PCAPNG=$(find tests/ -type f|xargs -L1 file|grep 'pcap-ng capture file')
PCAPNGCNT=$(echo -n $PCAPNG | wc -l)
if [ $PCAPNGCNT -ne 0 ]; then
    echo "pcap-ng tests found"
    echo $PCAPNG
    echo "PCAP-NG files are currently not allowed for tests due to not "
    echo "all platforms supporting it at this time. Please convert the "
    echo "pcap file(s) to regular pcap format: "
    echo "tshark -F pcap -r <pcapng file> -w <pcap file>"
    exit 1
fi

exit 0
