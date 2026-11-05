# Description

Test http2 events abour different host and authority

https://redmine.openinfosecfoundation.org/issues/6424

# PCAP

The pcap comes from running dummy HTTP2 server with `go run server.go`
and client `go run client.go`
and again client `go run client.go` uncommenting the auth headers and commenting the host ones
