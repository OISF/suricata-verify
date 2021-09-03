# Description

Test http2 file extraction over multiple transactions with range header.
# PCAP

The pcap comes from running dummy HTTP1 and HTTP2 server with `go run server.go` with an eicar.txt file in the current directory containing the eicar file
and in parallel as client(s) :
```
curl -H 'Range: bytes=0-10' --http2 127.0.0.1:8080/eicar
curl -H 'Range: bytes=10-20' 127.0.0.1:8080/eicar
curl -H 'Range: bytes=20-30' --http2 127.0.0.1:8080/eicar
curl -H 'Range: bytes=30-40' 127.0.0.1:8080/eicar
curl -H 'Range: bytes=40-68' --http2 127.0.0.1:8080/eicar
```
