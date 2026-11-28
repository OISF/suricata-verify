# nfs-keywords-name-handle

Covers the `nfs.name` and `nfs.handle` sticky buffers.

The capture is `nfs3-01`'s, referenced as `../nfs3-01/input.pcap`. The handle pattern is the root file handle of that capture as
`tshark -T fields -e nfs.fhandle` prints it, so sid 2 pins exact-bytes
matching on the buffer rather than a loose substring.
