# DNP3 G70V2 memory-amplification ASAN regression

This test covers the allocation behavior from Redmine issue 8827. The
deterministic capture contains a 512-point Group 70 Variation 2 request.

Affected builds allocate a decoded object containing two fixed 65536-byte
arrays for each 12-byte wire point. ASAN reports those objects in allocation
size-log bucket 17. The test enables ASAN allocator statistics and requires
fewer than 100 allocations in that bucket. During development, the affected
build reported 515 allocations and the fixed build reported 3.

This fixture is restricted to Linux ASAN builds because its regression oracle
depends on the allocator statistics emitted by ASAN.

Generated with:

```
./make-pcap.py
```

SHA-256: `2420aff6ed21a176d165ec99da94cc9aff6ce8a73193c931c2f1f3ea53d696d5`

Ticket: https://redmine.openinfosecfoundation.org/issues/8827
