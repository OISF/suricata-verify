Tests the behaviour of -T when a rule contains incomplete hex.

For Suricata 6.0.x, -T should pass unless
--strict-rule-keywords=content is provided.

For Suricata 7.0+, -T should fail.
