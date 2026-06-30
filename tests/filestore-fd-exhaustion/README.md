# filestore-fd-exhaustion

Regression test for the file-store open-file-descriptor accounting at the
default `max-open-files: 0`.

The default is documented as "files get closed after each write to the file",
so only a couple of descriptors are ever open regardless of how many files are
being extracted concurrently. A regression in `OutputFilestoreLogger` instead
keeps a descriptor open per in-progress stored file when `max-open-files` is 0,
so the count is bounded only by the number of simultaneous transfers — i.e. by
network traffic — and can exhaust the process file-descriptor table.

## How it works

`input.pcap` is 48 concurrent HTTP downloads whose bodies are delivered
round-robin, so every file is mid-transfer at the same time. Each file is
larger than the file-store incremental-write threshold (~100 KiB), so
file-store writes it while it is still open — that is what causes a descriptor
to be held on the affected build. The test runs Suricata with `force-filestore`
and a 32-descriptor `ulimit`:

- Correct build: closes after each write, ~1 fd open at a time, no error.
- Regressed build: holds ~48 fds at once, exceeds the limit, and logs
  `Filestore (v2) failed to create ... Too many open files` (EMFILE).

Note the extracted **file count is the same** either way (failed opens are
retried as other files close and everything flushes at EOF), so the check is on
the EMFILE log message, not on how many files were stored.

The pcap is ~6 MB because each of the 48 files must exceed the ~100 KiB
incremental-write threshold; that is the floor for this mechanism, not padding.

## Regenerate the pcap

    ./generate-pcap.py -o input.pcap

Requires scapy. The number of flows must stay above the `ulimit` set in
`test.yaml`.
