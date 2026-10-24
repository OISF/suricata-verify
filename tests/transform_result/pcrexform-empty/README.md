Test `pcrexform` on an empty capture and on an empty buffer. A capture of
nothing leaves an empty buffer, so content after `transform_result:
must_succeed` does not match the original URI (sids 1-2). An empty Referer
is left as it is and is not flagged as an error (sids 3-4).
