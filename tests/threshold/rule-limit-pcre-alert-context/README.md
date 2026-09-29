Threshold suppression of a rule that captures pcre groups with `alert:`.

Each match allocates the captured value for the alert, but only the alerts
that make it into the packet are logged and recycled with it. This test runs
both: sid 1 logs once and is suppressed for the rest of the flow, sid 2 logs
every packet.
