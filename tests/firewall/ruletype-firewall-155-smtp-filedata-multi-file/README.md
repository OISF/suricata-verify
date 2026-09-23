Test that a firewall LTE rule using file_data remains matchable across the
attachments of a single MIME message, so a later matching attachment still
triggers it even after an earlier non-matching attachment was inspected.

The DATA tx sends a multipart/mixed message with two attachments, streamed in
chunks so the attachments are added to the tx incrementally. The first
attachment (plain text) does not contain the content the rule looks for
(%PDF); the second attachment does. Once the rule matches the second
attachment the DATA tx is accepted, so the fail-closed default policy
(drop:flow) is not applied.

This pins the per file state reset in the detect engine: when a new file is
added to the tx the stored can't-match state of file inspect signatures is
cleared and the rule is re-evaluated, keeping it matchable. Run
`python3 gen_input_pcap.py` to regenerate input.pcap.

The tests also assert `fileinfo` records so the files under inspection are
verified to be tracked and closed complete.
