# Description

Test http2 host detection without :authority

https://redmine.openinfosecfoundation.org/issues/8774

# PCAP

The pcap comes from running dummy HTTP2 server with `go run server.go`
and client `go run h2_no_authority.go`
