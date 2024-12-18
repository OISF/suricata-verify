# Description

Test DNS over HTTP2 respects 65K UDP limit
https://redmine.openinfosecfoundation.org/issues/7464

# PCAP

Crafted with:
- a simple golang HTTP2 server always returning 415 http.StatusUnsupportedMediaType
- client `curl -H "content-type: application/dns-message" --http2-prior-knowledge  127.0.0.1:8080/dns -d @badns` with badns being a file over 65Kbytes

(I do not know why golang server sends many RST_STREAM at packet 45)
