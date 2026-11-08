Test invalid use of `transform_result: must_error` with content on the same
buffer after pcrexform. Verifies that combining must_error with another
keyword such as content on the same buffer fails to load with the expected
error message.
