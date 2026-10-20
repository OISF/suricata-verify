This test checks that one HTTP/2 Brotli decoder cannot reserve about 1 GiB
for one byte of request-body output. `input.pcap` contains locally generated
synthetic traffic with 34 connections and 4,000 active streams per connection.

https://redmine.openinfosecfoundation.org/issues/9008
