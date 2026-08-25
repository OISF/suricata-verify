Test http2 zstd decompression

https://redmine.openinfosecfoundation.org/issues/7904

Pcap crafted with
- go run server.go
- curl --http2-prior-knowledge http://localhost:8080/zstd
