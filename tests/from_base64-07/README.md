Test the `bytes` boundary of `from_base64`. When `bytes` equals the input
left after `offset`, the transform decodes all of it (8.0.x left such a
buffer undecoded). When `bytes` is larger, the buffer is left undecoded and
content matches the original URI.
