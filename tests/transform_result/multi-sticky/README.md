Test `transform_result` on a multi-value sticky buffer. http.request_header
is built by DetectGetMultiData (src/detect-engine.c), which runs the
transforms and then ORs DETECT_CI_FLAGS_SINGLE into the buffer flags, so the
error flag from_base64 sets reaches content inspection. With from_base64 in
strict mode, must_error fires and must_succeed does not.
