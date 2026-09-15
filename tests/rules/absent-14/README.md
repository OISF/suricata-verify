Test `absent: must_succeed` with from_base64. Validates that must_succeed
allows content matching only when the transform succeeds, and produces no
match when the transform fails — preventing false positives on the original buffer.
