Regression test: a segmented v4 COMPOUND WRITE under RPCSEC_GSS
rpc_gss_svc_none (cred procedure 0, service 1) must be scanned as a raw
compound (no envelope) and rejected with the write-size event, not the
scanner catch-all malformed discard. Regenerate:
python3 nfs4-gss-none-write.py (imports nfs_sv_common.py).
