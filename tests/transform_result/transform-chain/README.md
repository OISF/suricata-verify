Test `transform_result` when the transform that can fail is not the last in
the chain: `from_base64; to_uppercase`. The error flag from_base64 sets
survives to_uppercase, so must_error fires on the two bodies that fail to
decode, error_or fires on those two and on the decoded one, and must_succeed
fires only on the decoded one.
