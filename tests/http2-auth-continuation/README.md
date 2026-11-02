# Description

Test http2 host/authority mismatch when they are in 2 different frames

https://redmine.openinfosecfoundation.org/issues/6424

# PCAP

The pcap comes from running dummy HTTP2 server with `go run server.go`
and client `go run client.go`
