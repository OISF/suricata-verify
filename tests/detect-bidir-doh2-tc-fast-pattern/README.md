# detect-bidir-doh2-tc-fast-pattern

Transactional (`=>`) rules on a DoH2 (DNS over HTTP/2) POST whose fast pattern
is on the response half, in IDS mode (Redmine #9087). Such a rule is picked up
by the toclient inspection pass, which then evaluates the request half as
well.

## How the capture was made

`input.pcap` is a capture of real software: curl 7.76
with nghttp2 sends the POST over cleartext HTTP/2 (prior knowledge) to the DoH
listener of Unbound 1.24 configured without TLS (`http-notls-downstream`, as
it runs behind a TLS-terminating proxy), between two network namespaces joined
by a veth pair with 20 ms one-way delay.

## Scenario

One HTTP/2 stream, cleartext h2c on port 443 (pcap_cnt):

1-3   TCP handshake
4     client: HTTP/2 preface
5     client: SETTINGS
6     client: WINDOW_UPDATE
7     client: HEADERS `POST /dns-query` (content-type and accept
      `application/dns-message`, content-length 31)
8     client: DATA (DNS query for x.example.com, END_STREAM)
9-13  server: ACKs (13 acks the request)
14    server: SETTINGS
15    server: SETTINGS ack
16    server: HEADERS `200`
17    server: DATA (DNS response for x.example.com, END_STREAM)
18-21 client: ACKs (21 acks the response)
22    client: SETTINGS ack
23    client: FIN
24    server: FIN
25    client: ACK

In IDS mode the request is parsed on the server ACKs (12-13) and the response
on the client ACKs (20-21), so the transaction is complete in both directions
on a toserver packet; its toserver side is inspected there and marked done.
The first toclient packet afterwards is the server FIN (24): that pass runs
the rules whose fast pattern is on the response half, and must evaluate their
request half against the DNS request.

## Notes

* tshark renders the h2c frames on port 443 as `SSL Continuation Data`; decode
  with `-d tcp.port==443,http2`.
