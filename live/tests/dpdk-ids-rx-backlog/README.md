# DPDK IDS with the RX backlog enabled

Runs DPDK IDS on the AF_PACKET virtual PMD attached to `br0` with
`rx-backlog-size: 64`, covering the receive/process alternation of the
per-worker RX backlog and its `capture.dpdk.backlog.*` counters end to end.
The client pauses Suricata with SIGSTOP, floods 512 echo requests with a
256-packet preload, and resumes it: the PMD's kernel ring (sized to hold the
whole flood, since it cannot report overflow) then hands the worker full
32-packet RX bursts, which is what moves it into backlog mode independently
of the relative speed of the sender and the worker. Every echo request must
still alert, so the backlog may not drop or duplicate packets. The client
waits for those alerts before the runner stops Suricata, because packets
still in the NIC queue at shutdown are lost by design (the backlog itself is
flushed).
