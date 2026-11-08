# Redmine feature 9205 — frame embedded in a failed frame, option on

Same capture as `feature-9205-dnp3-recovery-embedded-default`, with
`app-layer.protocols.dnp3.resync-on-bad-start=yes`. After the bad block CRC the
parser searches for the next start sequence from the next octet, as a
resynchronizing endpoint does, so the request embedded in the failed frame is
parsed and marked with `dnp3.after_resync`. The rest of the failed frame
is then skipped as bad start bytes (`dnp3.bad_start_bytes`, a second error), and
the request after it is parsed and marked as well. In the second flow the
search from the next octet finds the start sequence in the failed response's
body and fails its link-header CRC (`dnp3.bad_link_crc`); the parser then
resynchronizes to the valid response, which is logged and marked.
