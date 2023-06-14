Test
====

Check and capture the behavior when Suricata is run with `exception-policy:
auto` set in IDS mode.

Behavior
========

We expect the master switch for exception policy to be set to `ignore` in that
case, as that's the default value in IDS.

We also don't expect to see any Warning message in that case, as that's expected
behavior.
