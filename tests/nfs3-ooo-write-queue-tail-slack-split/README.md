# NFSv3 record slack across a segment boundary

Same three WRITE calls as `nfs3-ooo-write-queue-tail-slack`. The difference is
that WRITE 2's 2048 bytes of in-record slack straddle two TCP segments: the
continuation carries the last 2000 file bytes and the first 1000 slack bytes,
and the next segment carries the remaining 1048 slack bytes.

All of the slack belongs to WRITE 2's record and must be drained to the record
boundary, so WRITE 3 lands on its marker and the file completes (7096 bytes,
sha256 5e9b7e94eb5255facf8f6eb3723b790f1d8eb413c42337530168804af7f000f5).
When the drain only covers slack that arrives after the record's last input,
the slack in the continuation segment is parsed as an RPC record: a
`malformed_data` anomaly, WRITE 3 lost and the file truncated at 1000 bytes.

Regenerate the capture with `python3 gen.py` (deterministic, no deps).
