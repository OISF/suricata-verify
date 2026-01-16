# Test

Test `http.form` keyword

# Ticket

https://redmine.openinfosecfoundation.org/issues/2487

# Pcap

Crafted with running:
- server: `go run server.go`
- client:
  * `curl -i -v "http://127.0.0.1:8080/toto?uriparam1=uv1&uriparam2=value%32" -d "bodyparam1=value1&bodyparam2=value%32"`
  * `curl --http2-prior-knowledge -i -v "http://127.0.0.1:8080/toto?uriparam1=uv1&uriparam2=value%32" -d "bodyparam1=value1&bodyparam2=value%32"param2=value%32"`

Output is as expected twice
> `bodyparam1=value1&bodyparam2=value2&uriparam1=uv1&uriparam2=value2`
