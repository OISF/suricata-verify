Regression test: a v3 LOOKUP reply whose record marker claims
1 MiB + 64 KiB (above the test's 1 MiB max-read-size + 64) must not be
buffered toward the crafted claim by the segmented-metadata gate. The
record is skipped to its claimed boundary (the filler sized to the
claim is eaten) and the reply never reaches the namemap: the follow-up
ACCESS on the reply's filehandle carries no filename. The filler also
pins the skip's boundary arithmetic (an off-by-N skip would eat into
or desync the follow-up record).
Regenerate: python3 nfs3-lookup-overclaim-skip.py (imports
nfs_sv_common.py).
