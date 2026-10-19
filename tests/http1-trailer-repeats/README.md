One HTTP/1 trailer name repeated 70 times in a chunked trailer section. The merged
buffer stops at the header repetition limit (occurrences 2..66), while the raw buffer
keeps all of them. Regenerate with `python3 make-pcap.py`.
