Test `transform_result: error_or` against bare `absent` with decode errors.
error_or matches on a decode error or on content, while bare `absent` only
matches a missing buffer and does not fire on a decode error. Covers strict
and rfc2045 modes.
