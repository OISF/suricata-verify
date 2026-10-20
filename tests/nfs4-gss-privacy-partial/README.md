# NFSv4 RPCSEC_GSS privacy records across segments

Three NFSv4 COMPOUND calls with an RPCSEC_GSS DATA/privacy credential
(procedure 0, service 3, as krb5p sends) and a 6000-byte encrypted body. Each
call and each reply is split over two TCP segments, as large krb5p WRITE calls
and READ replies are on the wire. One PUTFH+REMOVE call with no reply comes
first, so a live transaction is around to be stamped by accident.

A privacy compound is encrypted. Neither the partial-record scan nor the record
parser can read it, and it is not malformed. The scan must skip such a record to
its boundary, in both directions, rather than reject it on a `malformed_data`
transaction of its own; the reply parser must not run on an encrypted
COMPOUND4res at all, since its failure would land on the newest transaction.

Regenerate the capture with `python3 gen.py` (deterministic, no deps).
