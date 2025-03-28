#!/bin/bash
  
#set -x

BADPCAPCNT=$(find tests/ -type f|xargs -L1 file|grep "pcap capture file, microsecond ts, extensions"|wc -l)
if [ $BADPCAPCNT -ne 0 ]; then
    echo "$BADPCAPCNT unsupported pcap files found:"
    echo
    find tests/ -type f|xargs -L1 file|grep "pcap capture file, microsecond ts, extensions"
    echo
    echo "pcap files with extensions are not supported by OpenBSD"
    exit 1
fi

exit 0
