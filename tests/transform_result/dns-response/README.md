Test `transform_result` on dns.response.rrname, a multi-value sticky buffer
built by its own InspectionBufferSetupMulti caller in
src/detect-dns-response.c. That caller ORs DETECT_CI_FLAGS_SINGLE into the
buffer flags after the transforms run, so the error flag from_base64 sets
reaches content inspection. With from_base64 in strict mode, must_error
fires and must_succeed does not.
