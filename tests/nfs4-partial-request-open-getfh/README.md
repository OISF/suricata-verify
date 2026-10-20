# Segmented OPEN request compound: the scanner must skip the OPEN (request)

NFSv4: a PUTFH; OPEN (CLAIM_NULL, open_type 0); GETFH request compound
with the record padded past 512 bytes via the OPEN's owner name, split
right after the OPEN tag. The OPEN (request) is a valid op the full
parser supports but had no scanner skip entry, so a fragmented record
was rejected as malformed and the OPEN's filename association was lost:
the following PUTFH; READ (same handle, via the GETFH result) gets no
filename. Checks: no malformed data, the read file is logged (size
8192) and carries the OPEN's filename in the fileinfo and the nfs
event.
