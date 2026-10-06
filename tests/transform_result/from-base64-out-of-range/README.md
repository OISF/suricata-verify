Test `transform_result` when `from_base64` has nothing to decode. An
`offset` past the end of the buffer (sids 1-2) or exactly at it (sids 8-9),
or `bytes` larger than the input left after `offset` (sids 3-4, 7), leaves
the buffer undecoded and signals an error: must_succeed does not fire,
while must_error and error_or do. Sid 5 shows content still matches the
undecoded URI without transform_result, and sid 6 shows that `bytes` equal
to the input left after `offset` decodes all of it.
