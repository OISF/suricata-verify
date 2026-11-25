Test `gunzip` and `zlib_deflate` on data that is not compressed. The
decompression fails, the transform keeps its input and flags an error, so
must_error fires, must_succeed does not, and content matches the original URI
(sids 1-3). After `strip_whitespace` the input is in the buffer's own memory,
and zlib_deflate still leaves it as it was (sids 4-5).
