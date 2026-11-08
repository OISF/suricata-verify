Test `from_base64` on an empty buffer. The request has a Referer header with
an empty value (sid 1). from_base64 leaves the empty buffer as it is (sid 2)
and does not flag an error, so neither must_error (sid 3) nor error_or
(sid 4) fires.
