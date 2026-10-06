Tests the Authenticode signing-certificate options of the `windows_pe`
keyword. The signed PE embeds a PKCS#7 certificate table; the fixture also
carries an unsigned PE. Verifies the bare `signature` presence flag,
`cert_thumbprint` (exact and a negative test), `cert_serial`
(separator-insensitive), and `cert_subject`/`cert_issuer` substring matches,
plus the `executable.signed` EVE field for both signed and unsigned files.

The signing certificate is matched but not cryptographically verified. The
`input.pcap` is a frozen fixture built with a fixed key; see the
`pe-keyword-validation` bundle's `common/pcap-generators/gen_pe_fixtures.py`
for how it is generated.
