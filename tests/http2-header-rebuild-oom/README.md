# Description

HTTP/2 request whose 100000-byte HPACK header block puts one 65503-byte
header in the dynamic table and then references it 34483 times by index.

The `bsize` rules assert that the inspection buffers stay bounded, the
`too_long_repeated_headers` event is raised and the logged request
headers are deduplicated as well.

# Ticket

https://redmine.openinfosecfoundation.org/issues/9185
