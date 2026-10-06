# Redmine #8853 short SSLv2 CLIENT_HELLO record

Regression test for https://redmine.openinfosecfoundation.org/issues/8853.

After a TCP handshake, the client sends the ticket's exact nine-byte SSLv2
payload: `80 01 01 00 02 00 00 00 00`. The declared record length is one,
which cannot contain the six fixed CLIENT_HELLO bytes. A fixed parser reports
`tls.invalid_ssl_record`; the old parser underflowed its remaining-length
calculation and desynchronised the record stream.

Regenerate the pcap with `./make-pcap.py`.
