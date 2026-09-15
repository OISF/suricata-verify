Test invalid use of `absent: must_error` with multiple keywords on the
same buffer. Verifies that combining must_error with other keywords
(transform + content) on the same buffer fails to load with the proper
error message.
