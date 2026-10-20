Test that `transform_result: must_error` and `error_or` ignore a decode
error on part of a body. Flow 1 posts 60000 bytes of valid base64, which
`http.request_body` and `file.data` inspect in windows; a strict decode of
a window cut off a 4-byte boundary fails, and that must not raise an alert.
Flow 2 posts a short body that is not base64, inspected in one piece, and
its decode error does raise one.
