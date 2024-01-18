# Description

Test dns schema completion and sshfp parsing
https://redmine.openinfosecfoundation.org/issues/5642

# PCAP

The pcap comes from running `dig SSHFP anoncvs.netbsd.org`
+ manual modification to set `dns.flags.truncated` to true to test `tc` field
