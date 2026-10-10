# Redmine feature 9205

DNP3 link-layer recovery with `app-layer.protocols.dnp3.resync-on-bad-start`
enabled, on the capture of `feature-9205-dnp3-recovery-default`.

With the option on, octets without a start sequence are skipped and
`dnp3.bad_start_bytes` is set: the request behind them is logged in flow 2
(mid-stream) and in flow 4 (start of flow, through the probing parser), and
both are marked with `dnp3.policy_divergence`. Flow 3 (bad link-header CRC)
behaves as with the option off. The baseline flow raises no event.
