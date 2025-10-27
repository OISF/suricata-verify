Purpose
-------
Validate that detection_filter with unique_on src_port does not trigger when
the number of distinct source ports stays below the threshold.

Rule requires 3 distinct source ports for the same source host (track by_src).
The PCAP only has 2 distinct source ports, so the threshold is not reached
and no alerts are expected (sid 100012).

Why this matters
---------------
Ensures duplicates or insufficient variety of src ports do not produce alerts
when distinct counting (unique_on src_port) is configured with a higher threshold.


