A chunked request and response whose trailer sections carry no fields
("0\\r\\n\\r\\n"). Only the section terminator is on the wire, so no trailer
buffer must exist: a rule anchored on http.trailer.raw must not match every
chunked message. Regenerate with `python3 make-pcap.py`.
