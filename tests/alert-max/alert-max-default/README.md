Tests that even if we have higher priority rules, if they have the `noalert`
keyword, a later triggered `alert` rule will be appended and generate an alert.

The `noalert` rules show up in our stats log as `detect.alerts_suppressed`.
The alert rule will be triggered.

Also test that Suricata will fall back to default value if an invalid value
(zero, in the test) is passed in the configuration file.
