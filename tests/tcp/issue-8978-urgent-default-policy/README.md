# Missing TCP urgent policy defaults to out-of-band

Redmine #8978, backport #8990.

With `stream.reassembly.urgent.policy` absent, urgent data must receive the
same out-of-band treatment as with the shipped explicit `oob` setting.
The local configuration deliberately omits the entire urgent section;
using the engine's shipped configuration would not exercise the fallback.

The stream, HTTP URI and HTTP request-frame rules must all see `malicious`,
which is split by an urgent out-of-band byte in the capture. A fallback to
inline treatment leaves that byte in the stream and misses those matches.

## PCAP and rules

Reuses upstream's `../../tcp-urgp-01-oob/tcp-urgent1.pcap` and
`suricata.rules`. The existing test supplies the explicit-policy control;
this test retains the same three expected alerts with the key omitted.
No new capture is generated.
