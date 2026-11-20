Test valid use of `absent: or_else` with a non-failing transform.
Validates that `or_else` paired with a transform not marked
`SIGMATCH_TRANSFORM_CAN_FAIL` (`strip_whitespace`) loads successfully
without errors.
