Test invalid use of `absent: must_succeed` without a failing transform.
Verifies that rule loading fails when must_succeed is used on a buffer
with no transform that can signal an error.
