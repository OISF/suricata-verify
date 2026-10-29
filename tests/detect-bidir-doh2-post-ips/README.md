# detect-bidir-doh2-post-ips

Coverage for the bidirectional (`=>`) pair engine on a DOH2 (DNS-over-HTTP/2)
POST flow, run in IPS mode. A toclient DOH2 engine such as
`dns.response.rrname` must keep the pair pending on an HTTP/2/DOH2 flow while
the DNS response is still pending, not be treated as a wrong-variant engine
just because the flow has not yet been forced to DOH2 (Redmine #9087).

## Why IPS mode

In IPS mode each TCP segment is parsed as it arrives, so the request HEADERS
(pcap_cnt 5) are seen before the request DATA (pcap_cnt 6). On the first
request's HEADERS the flow is still `ALPROTO_HTTP2` - it is forced to DOH2 only
once the first DNS message parses
(`SCAppLayerForceProtocolChange`, rust/src/http2/http2.rs:626/:635/:1580). That
HEADERS-only window is where a toclient DOH2 engine must still hold the pair
open; a DOH2-only pendency check (waiting for `f->alproto == ALPROTO_DOH2`)
instead treats the engine as wrong-variant and closes the pair on the toserver
half alone.

In IDS mode (`-k none` without `--simulate-ips`) the HEADERS and DATA are parsed
together on the server ACK (pcap_cnt 7), so the window never occurs and the test
cannot pin the behaviour. This variant therefore runs with `--simulate-ips`.

## Scenario

A single HTTP/2 stream (pcap_cnt):

1-3   TCP handshake
4     client: HTTP/2 preface + SETTINGS
5     client: HEADERS `POST /dns-query`, `content-type:
      application/dns-message`  <- request HEADERS, no DNS yet, flow still HTTP2
6     client: DATA (DNS query for x.example.com), END_STREAM
7     server: ACK
8     server: SETTINGS
9     server: HEADERS `200 OK`, `content-type: application/dns-message`
10    server: DATA (DNS response for x.example.com), END_STREAM
11    client: ACK
12-14 teardown

Suricata classifies the flow as DOH2 (the `application/dns-message` content type
plus the `/dns-query` path) and parses the inner DNS request/response.

## Rules

* **sid 1** `http.uri /dns-query` (toserver) `=>` `dns.response.rrname x`
  (toclient). The response echoes the query name `x.example.com`, so the
  toclient half matches. The pair may only close once the DNS response is
  parsed (pcap_cnt 10) - never on the request HEADERS (pcap_cnt 5) alone.
* **sid 2** the same pair whose response condition
  (`dns.response.rrname nomatchzzz`) never matches. It must never alert: the
  request HEADERS alone is not a full match.

## Checks

* sid 1 alerts exactly once, at pcap_cnt 10 (after the response); an unfiltered
  `count: 1` and a `pcap_cnt: 10` pin.
* sid 2 never alerts.
* the inner DNS response is parsed (pins the exchange).

## Notes

* `input.pcap` is produced by `gen_input_pcap.py` (byte-identical across
  runs); regenerate with `python3 gen_input_pcap.py`.
* The traffic is cleartext HTTP/2 (h2c) on port 443, so `tshark` decodes the
  first frame (HTTP/2 magic + SETTINGS) but renders the subsequent HEADERS/DATA
  frames as generic `SSL Continuation Data` (it assumes TLS on 443); it cannot
  fully dissect the raw H2/DoH2 stream without a TLS record. The pcap is
  validated structurally with `tshark -r input.pcap` and the DNS/HTTP2 events
  are confirmed from Suricata's own eve-log output.
