Regression test: a v3 READDIRPLUS reply (one entry) split across two
TCP segments must be parsed (not skipped), so the entry's
handle->name mapping reaches the namemap; a follow-up ACCESS on the
entry's handle then carries the filename. (The follow-up is ACCESS,
not GETATTR, because v3 GETATTR txs are filtered out of the eve log
by design: SCNfsTxLoggingIsFiltered.) A client ACK separates each
segment so the stream engine feeds the app layer the partial record
first. Regenerate: python3 nfs3-readdirplus-segmented.py
(imports nfs_sv_common.py).
