# Test Description

Test HTTP1 with usage of `+` in URI

# Ticket

https://redmine.openinfosecfoundation.org/issues/8130

# Pcap

Crafted with:
- `go run server.go`
- `curl -i -v "http://127.0.0.1:8080/toto+t%61ta?param=value&enc=after+sp%61ce"`

- `go run server2.go`
- `curl -i -v --http2-prior-knowledge "http://127.0.0.1:8080/toto+t%61ta?param=value&enc=after+sp%61ce"`
