# DHCP malformed and truncated options

This test verifies that DHCP option parsing errors are classified according to
whether sufficient data is present.

Valid renewal-time options following malformed time options in the primary and
overloaded `sname` streams must still trigger `dhcp.renewal_time` detection and
appear in DHCP logs.

