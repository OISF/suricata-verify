Test `transform_result` on `file.data` with `from_base64`, using three HTTP
request bodies: two that fail to decode and one that decodes to
"decoded-content". must_error fires on the two failures, must_succeed
fires only on the decoded match, error_or fires on all three, and
must_succeed keeps content from matching text that exists only in an
undecoded body (sid 5 shows that text does match without transform_result).
