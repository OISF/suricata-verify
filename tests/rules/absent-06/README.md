Test `absent: error_or` vs bare `absent` with decode errors. Validates
the difference between error_or (matches on error OR content) and bare
absent (only matches NULL buffers) across strict and rfc2045 modes.
