# HTTP/2 Brotli memcap visibility

Redmine: https://redmine.openinfosecfoundation.org/issues/9104

Verify that exhausting the process-wide 256 MiB HTTP/2 Brotli allocator cap
produces both an EVE `failed_decompression` anomaly and the shipped event-rule
alert, SID 2290009. This tests allocation denial, rather than rejection of an
unsupported Brotli window, invalid compressed data, or a compression bomb.

## Traffic

`input.pcap` contains real HTTP/2 traffic generated and captured in a lab.

The connection carries these requests:

1. `/control`: a small complete Brotli response, inspected successfully.
2. `/hold/0` through `/hold/14`: send only the first 64 encoded bytes of each
   response, leaving all 15 streams open. Each uses a standard 24-bit window
   and a non-final metablock. The Brotli decoder reserves a 16 MiB ring plus
   overhead for each stream despite the small body prefix.
3. `/pressure` (stream 33, EVE transaction 18): another such response. Its
   first DATA frame needs another 16 MiB plus overhead, exceeding the cap.
   The remaining encoded bytes follow in a second DATA frame and the real
   client successfully decodes the complete 1,024-byte body. Suricata reports
   `failed_decompression`. The unmodified bidirectional SID 2290009 alerts
   once in each direction for this transaction.
4. `/release`: finish all held responses. Their decoded files must each have
   the expected 1,024-byte size.
5. `/recovery`: another response using the same 24-bit-window construction.
   After the held transactions are released, body inspection succeeds and
   the decoded file has the expected 1,026-byte size.

This stays well below the default 256-stream limit and does not expand enough
data to hit the compression-bomb limit. Exactly one anomaly is expected, on
the pressure transaction. The cap is deliberately left at its default.

The capture is replayed in single runmode with checksum validation disabled.
