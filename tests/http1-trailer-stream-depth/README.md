# HTTP/1 trailer block cut by stream reassembly depth

The last chunk opens the trailer section, two trailer fields follow and filler then pushes the
direction past `stream.reassembly.depth`, so no trailer state hook can run. The peer
acknowledges every segment, which is what makes the delivered bytes visible to htp at all.

With the block cut this way the trailer buffers must still hand over what was parsed, matching
what main does for the same bytes through its `http.header` buffer. Flow B sends the same
traffic with a properly terminated trailer block.

Needs the trailer buffers, so it is expected to fail before the engine side lands.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
