# SMTP log limits

A session with 100 `RCPT TO` entries: the logger caps the list at 64
entries / 32 KiB, sets `rcpt_to_truncated` and the aggregate `truncated`
marker, and keeps the record bounded.

`generate_pcap.py` is deterministic; `smtp.pcap` is the committed output,
checked with tshark.
