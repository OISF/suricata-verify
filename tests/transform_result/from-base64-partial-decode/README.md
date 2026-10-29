Test `from_base64` on input with invalid bytes in the middle. In rfc4648
mode the decoder stops at the invalid bytes and the buffer keeps what was
decoded before them; that counts as success, so must_error does not fire and
must_succeed does (sids 1-3). In rfc2045 mode the invalid bytes are skipped
and the whole input decodes (sids 4-5). Strict mode rejects the input and
flags an error (sid 6).
