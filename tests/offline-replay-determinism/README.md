# offline-replay-determinism

Replaying the same capture must give the same answer, no matter which thread a
packet ends up on and no matter how fast the host is.

Two tuples over 4 workers. Tuple A carries a connection at t=0 that is never
closed, and a second connection on the same tuple at t=30. Tuple B sends one
packet per second until t=29.6 and is what moves the clock. At most two of the
four workers ever see a packet, so at least two of them hold the oldest packet
timestamp of the run at zero. Offline time is that oldest timestamp, so the
question is what "too far behind to count" means: measured in host time, an idle
worker is fresh for the first 5 s of the run and the clock stays at t=0, and every
event of the run gets stamped at the first second of a capture that ran for 30;
measured in packet time the idle workers do not count and the clock follows B.

`check-clock.py` is the marker: a flow event may not be stamped more than a second
before the last packet of the flow it reports. That fails on a build without the
packet-time window and passes with it. The rest pins what the run must always
give: 2 alerts on the two connections of tuple A, 1 on the payload of B, 2 flows,
`tcp.pkt_on_wrong_thread` 0, and a second replay that compares `IDENTICAL`.

Workers are pinned with `threading.set-cpu-affinity` plus
`cpu-affinity: worker-cpu-set: threads`. Without `set-cpu-affinity` that node is
never read (runmodes.c:961) and the worker count follows the CPUs of the host,
and with it which worker holds the oldest timestamp. The warning `No CPU affinity
set for threading.cpu-affinity.worker-cpu-set` is expected: only the count is
wanted, pinning to CPU ids would break hosts with fewer of them.

test.pcap comes from `make-pcap.py`. B has to stay busy for more than the 5 s
window, else the idle workers are not behind in packet time either and the two
agree again. The keep alive segments have to be a contiguous stream: they are 6
bytes each and the first one continues B-START, so the sequence numbers advance by
6 from 5008. The clock change itself is also pinned at unit level, by
TmThreadsTestMinimalTimestamp01..05 in `src/tm-threads.c`: 02 is a busy worker that
is behind in the file and must keep holding the clock back, 04 is a worker that
never saw a packet and must not, and it is 04 that fails on unfixed main.
