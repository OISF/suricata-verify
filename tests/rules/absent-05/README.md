Test invalid use of `absent: error_or` with a non-failing transform.
Verifies that error_or with a transform that cannot fail (dotprefix)
causes a fatal error during rule loading.
