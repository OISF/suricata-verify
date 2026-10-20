Test that a failed `from_base64` decode keeps the original bytes when another
transform runs first. After `strip_whitespace`, the buffer holds its own copy
of the URI, and from_base64 decodes from and into that same memory. Strict
mode decodes "foobarbazqux" and then fails on "!!". The buffer must still hold
the original URI (sid 1), with no decoded bytes in it (sid 2) and the error
flagged (sid 3). Sid 4 runs the same decode with no transform before it.
