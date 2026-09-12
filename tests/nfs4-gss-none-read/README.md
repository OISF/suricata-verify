Regression test: a v4 COMPOUND READ under RPCSEC_GSS rpc_gss_svc_none
(cred procedure 0, service 1) with a segmented reply claiming 8 KiB but
carrying a 17 MiB inner READ claim: the reply-side scan must treat the
raw compound as scan data and reject with the read-size event, not the
scanner catch-all malformed discard. Regenerate:
python3 nfs4-gss-none-read.py (imports nfs_sv_common.py).
