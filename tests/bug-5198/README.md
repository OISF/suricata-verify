This test covers the conditions described in issue 5198. An ASAN-enabled build is required for verification as the problem does not present
on a build without ASAN.

The problem occurs when
- Eve threaded logging is enabled
- Suricata doesn't have permissions to create the eve output file

An ASAN build is required to detect the condition (see the issue for the ASAN diagnostics)
