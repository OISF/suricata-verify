Test `transform_result: must_succeed` with pcrexform on http.request_line.
When the regex matches, content inspects only the extracted text; when it
does not match, must_succeed keeps content from matching the original line
(sid 4 shows the original line does match without transform_result).
