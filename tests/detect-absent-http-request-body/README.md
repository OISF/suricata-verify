# Test Description

Test `absent` keyword with `http.request_body`

## PCAP

Manually crafted with server
`python3 -m http.server`
and client
`curl -X POST http://127.0.0.1:8000/toto`

## Related issues

https://redmine.openinfosecfoundation.org/issues/2224
