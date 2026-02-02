Test invalid use of `absent: error_or` with a non-failing transform.
Verifies that `error_or` paired with a transform not marked
`SIGMATCH_TRANSFORM_CAN_FAIL` (`strip_whitespace`) causes a fatal error
during rule loading.
