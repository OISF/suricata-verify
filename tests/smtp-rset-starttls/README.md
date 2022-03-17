# Description

Test smtp against bug https://redmine.openinfosecfoundation.org/issues/4948

# PCAP

The pcap comes from an oss-fuzz reproducer, and was crafted with fuzzpcap, to add the ehlo sequence to get first recognized as SMTP.
