Test `transform_result` when the can-fail transform is not the last in the
chain: `from_base64; to_uppercase`. The error flag from_base64 sets survives
to_uppercase, so must_error and error_or fire on the two bodies that fail to
decode and must_succeed fires only on the decoded one.
