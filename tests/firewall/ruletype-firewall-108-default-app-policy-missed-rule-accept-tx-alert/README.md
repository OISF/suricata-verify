Test that a default app policy of accept:tx,alert behaves like accept:tx when
an explicit rule exists for the same hook but does not match. This exercises the
fw_last_for_progress miss path for multi-action accept policies. In this test
there is an addional rule for the next hook.
