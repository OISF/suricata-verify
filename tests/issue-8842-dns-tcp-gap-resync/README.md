Reproduce Redmine issue 8842: an invalid DNS-over-TCP slice after a
to-server reassembly gap must be ignored so that parsing can resynchronize on
the next valid DNS request.

Run `./make-pcap.py` to regenerate `input.pcap` deterministically. Its SHA-256
is `4e1f0e3740831b43390e4da226712f314e7dc2fdfc56098cde3764b7eb1eab72`.
