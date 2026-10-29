Protocol detection registers the server response patterns (`* OK `, `* LIST `,
etc.) on the to-client side, and a probing parser bound to the default port
143. On any other port, a capture that contains only client traffic has no
server bytes for those patterns to match and never reaches the probing parser.

This test drives a single client `a001 CAPABILITY` command over port 1143 with
no server response. Detection succeeds only via the port-independent
request-side CAPABILITY pattern, so the flow record must report `app_proto:
imap`. Without that pattern the flow is left unidentified.

The request probing parser reports incomplete until a command line ends in
CRLF, and the detection engine permanently masks a probing parser once the
buffered input passes its 16-byte window while still inconclusive. A client
command split so its first segment exceeds 16 bytes with no CRLF was therefore
left unidentified, even though the same command in a single segment is
detected.

This test sends `A1 LOGIN username ` as an 18-byte first segment, a server ACK,
then `password` and CRLF. The intervening ACK forces the first segment to reach
protocol detection alone; otherwise reassembly coalesces the two segments and
the probe sees the whole command. Detection must recognize IMAP from the
`tag command` prefix, so the flow record reports `app_proto: imap`.

