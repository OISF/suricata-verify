# Description

Test http gap handling

This test case contains a single simple gap in response body with defined content-length

# PCAP

The pcap comes from running
`python test/htptopcap.py toaddgap.txt`
With the attached toaddgap.txt

Then removing packet 17
