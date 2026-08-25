# Description

Test http1 gzip decompression with chunked encoding and stop in the middle of the CRC

https://redmine.openinfosecfoundation.org/issues/8850

# PCAP

The pcap comes from running dummy HTTP2 server server.py and `curl -i -v http://127.0.0.1:8002/toto`
