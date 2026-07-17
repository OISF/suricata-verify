Test `absent: error_or` with pcrexform transform. Validates that
error_or matches on transform failure OR content match, and does not
match when the transform succeeds without a content match.
