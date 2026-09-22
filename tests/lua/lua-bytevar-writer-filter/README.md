Reproducer: bytevar slots are per-detect-run state with writer
identity. sid:1's extractor writes slot 0 before sid:2's lua keyword
runs (smd order: dns.query -> lua -> byte_extract, sid 1 before sid 2),
so value() must return nil for sid:2's handle: the slot's writer is
not this signature. Without the per-signature writer filter the raw
shared slot carries sid:1's value and the rules never alert.
