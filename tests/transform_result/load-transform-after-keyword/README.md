Test the load error for a transform placed after `transform_result` or
`absent: or_else`. The transform starts a new buffer and the content after it
goes there, so the keyword is left alone on the first buffer. The error says
the keyword must come after the buffer's transforms. A later buffer with no
transform does not count, and that rule gets the usual error instead.
