# Description

Test http2 content-encoding case insensitivity

https://redmine.openinfosecfoundation.org/issues/8760

# PCAP

The pcap comes from running dummy HTTP2 server with `go run server.go`
and client `curl --compressed -H 'Accept-Encoding: deflate' --http2 127.0.0.1:8080/` and seeing the decompressed output
