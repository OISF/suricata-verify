# Description

Test http2 reassembly of header + continuation frames

https://redmine.openinfosecfoundation.org/issues/5926

The alert check also verifies that END_STREAM does not complete header
inspection before the final CONTINUATION frame has supplied END_HEADERS.
Enabled for the 8.0.8 backport:
https://redmine.openinfosecfoundation.org/issues/9218

# PCAP

The pcap was produced with a crafted client against a go server
