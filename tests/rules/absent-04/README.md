Test invalid use of `absent: error_or` without a failing transform.
Verifies that error_or on a buffer with no transform causes a fatal
error during rule loading.
