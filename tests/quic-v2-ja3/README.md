# Description

Test quic v2 parsing

# PCAP

The pcap comes from running https://github.com/quic-go/quic-go

The example server is in example
`go run main.go -bind localhost:443`
The example client is in example/client
`go run main.go -insecure https://127.0.0.1:443/`
with this patch
```
+qconf.Versions = []quic.VersionNumber{quic.VersionNumber(0x6b3343cf)}
```
