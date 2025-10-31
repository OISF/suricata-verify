Tests that Suricata properly validates the `force-hash` configuration option
for EVE file logging and rejects invalid hash algorithm names.

Expected Behavior
=================

Suricata should detect the invalid `force-hash` algorithm 'shanani' in the
configuration and exit with code 1, outputting an error message indicating
that the algorithm must be one of: md5, sha1, or sha256.

The test checks that the expected error message appears in either suricata.log
or stderr output.

