# HTTP/1 response header block cut by stream reassembly depth

The to_client counterpart of `http1-depth-headers-ts`: the request completes, the response
header block is cut by the depth limit, and the peer acknowledges what was sent. Both
directions must be inspected, so the raw rules on request and response match, with a
`content` on the response bytes as the positive control that data reached detection.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
