# lua-luaxform-empty-result

A valid empty transform result: on a non-`KEEP` body the script returns
an empty string with an explicit zero length. Zero must stay an accepted
length and must not be counted as a transform error - the rejection is
pinned to a non-numeric second result, not to the value zero.

An accepted empty result must leave the buffer as it was, for every
thread history. Before the fix, the empty result reached
`InspectionBufferCopy` with a zero length: a no-op on a buffer that had
never been expanded (the body kept its content) but a buffer-emptying
copy once an earlier transform on the thread had expanded it - so the
second session matched or not depending on what the thread inspected
before. The fix skips the copy for a zero length.

The two sessions run that history on one thread (`--runmode=single`;
under autofp they could land on different workers). The first body
contains `KEEP` and the script returns the input, expanding the thread's
inspection buffer; the second gets the empty result. Both bodies carry
the matched content, so both sessions alert on the fixed engine; the
old engine fires only the first.

input.pcap: two HTTP/1.1 GET + 200 sessions, bodies
`KEEP GONE marker1` and `GONE marker2`
(`python3 mkpcap.py input.pcap <b64 body1> <b64 body2>`).
