Rules on a dns response buffer stop alerting on a doh2 flow as soon as the
ruleset also holds an http2 rule (sid 30), even though that rule cannot match
the capture.

Expected: sids 20 and 21 alert twice each, as they do in
dns-over-http2-response-ok, which is the same test without sid 30.

Ticket: 9268
