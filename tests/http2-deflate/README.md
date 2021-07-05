# Description

Test http2 deflate decompression

# PCAP

The pcap comes from running dummy HTTP2 server with `go run server.go`
and client `curl -H 'Accept-Encoding: deflate' --http2 127.0.0.1:8080/`
