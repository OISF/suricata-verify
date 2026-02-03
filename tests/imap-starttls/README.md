Three flows negotiate STARTTLS and then perform a TLS handshake. In the first,
the server sends an untagged response between the STARTTLS command and its
tagged OK; in the second it replies directly; in the third STARTTLS is
pipelined after an AUTHENTICATE that the server rejects without asking for
data. All flows must switch to TLS on the tagged STARTTLS reply, yield a tls event attributed to imap, and raise no
parser error or `imap.invalid_data` event.
