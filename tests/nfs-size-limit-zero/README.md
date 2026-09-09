# nfs-size-limit-zero

`max-read-size: 0` and `max-write-size: 0` are documented as disabling the
size checks. This test transfers 17.5 MiB in each direction — above the
16 MiB defaults — with both limits set to zero:

- a small v3 WRITE first (complete first record in each direction, so
  the app layer attaches),
- a v3 WRITE of 17.5 MiB total (offsets 0 and 8, FILE_UNSTABLE, non-
  overlapping) followed by WRITEOK replies,
- a v3 READ request for the same total size and a 17.5 MiB READ reply
  (eof) on a distinct file handle.

With the zero limits accepted, no `*_too_large` event may fire and both
transfers must complete with the full 18350080-byte file size logged in
fileinfo (the stream reassembly depth is raised via `--set` because the
transfers exceed the default 1 MB depth).

If a zero limit were rejected at config time, the 16 MiB defaults stay
active and both 17.5 MiB transfers are rejected with too-large events
instead.
