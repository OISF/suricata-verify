Test 2 UDP DNS requests followed back to back with no response, then
the 2 responses being received.

Prior to Suricata 3.2 the first request would be marked as having a
reply lost when the second request was seen.

Related issue:
https://redmine.openinfosecfoundation.org/issues/1923
