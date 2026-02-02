Test `absent: must_error` with from_base64 strict mode. Validates that
must_error alerts on strict mode decode errors and does not alert when
rfc2045 mode decodes successfully.
