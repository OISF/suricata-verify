Reproducer for lua/dns: recursion_desired() is always false. The FFI
getter returns the rcode-masked response flags and the Lua side tests
0x0080, which can never be set; RD also lives in the request header.

The test pcap has RD=1; the script requires at least one true result.

Ticket: #9082.
