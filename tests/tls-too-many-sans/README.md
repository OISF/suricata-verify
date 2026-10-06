# tls-too-many-sans

Ticket: 8864

A TLS server certificate whose subjectAltName extension holds **65537**
entries -- one more than fits in the `u16` that
`SCX509GetSubjectAltNameLen()` returns to `TlsDecodeHSCertificate()`.

The parser used to return `general_names.len() as u16`, a truncating cast.
65537 wraps to 1, so Suricata saw a single-entry SAN list: every entry past
index 0 vanished from `tls.subjectaltname` matching and from `eve.json`, with
nothing logged to say so. The count is now saturated at `4k` instead,
and a count that saturates raises
`tls.too_many_subject_alternative_names`.

## The certificate

`input.pcap` is synthetic; regenerate it with `python3 generate-pcap.py`
(needs scapy). The SAN list is laid out so truncation is observable:

| index      | dNSName        | purpose                                              |
|------------|----------------|------------------------------------------------------|
| 0          | `a`            | decoy -- the only entry a truncated count exposes     |
| 1          | `evil.example` | detection target, visible only once the count saturates |
| 2..65536   | `b`            | 1-byte filler to push the count past `4k`       |

Filler keeps the certificate at ~197 KB rather than the ~920 KB it would take
to repeat `evil.example` 65536 times. That stays clear of the default 1 MiB
`stream.reassembly.depth` and well under the 24-bit handshake-message and
`cert_chain_len` limits.

The certificate is hand-rolled DER: a v3 self-signed skeleton with a
syntactically valid but cryptographically meaningless RSA key. Suricata only
parses the DER, it never verifies the signature.

The server flight is a TLS 1.2 ServerHello, the Certificate message split
across 16384-byte records so it exercises the `hs_buffer` reassembly path, and
a ServerHelloDone. Both peers advertise a 65535-byte TCP window and the client
ACKs every four segments -- with a smaller window the ~200 KB flight falls
outside it and the stream engine stops feeding the TLS parser.

## What is checked

- `sid:2230032` -- the new event fires.
- `sid:1000001` -- `tls.subjectaltname` still matches `evil.example` at
  index 1, i.e. detection reaches past the index a truncated count exposed.
- `tls.subjectaltname` is logged with exactly 65535 entries, `a` first and
  `evil.example` second.

Against the truncating cast all three fail, and `eve.json` carries
`"subjectaltname":["a"]`.

`sid:2230032` is the next free sid in the 2230000+ TLS event range. Note that
`rules/tls-events.rules` in the Suricata tree does not yet carry a rule for
this event, so the rule lives here for now; it is written to be copied over
verbatim.
