#!/usr/bin/env python3
"""Compare two Eve files of the same capture replayed twice.

Prints IDENTICAL when the runs agree, else the differing counts. The record
counts by event type, the alerts per rule and the flows per state and direction
are what a replay may disagree on, so those are the summary. Timestamps, flow
ids and the stats record are left out on purpose: they are not expected to be
the same from run to run.
"""

import json
import sys
from collections import Counter


def summarize(path):
    summary = Counter()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = event.get("event_type", "?")
            summary["event:" + etype] += 1
            if etype == "alert":
                alert = event.get("alert", {})
                key = "alert:sid=%s,rev=%s" % (alert.get("signature_id"), alert.get("rev"))
                summary[key] += 1
            elif etype == "flow":
                key = "flow:%s,%s" % (event.get("proto", "?"), event.get("flow", {}).get("state", "?"))
                summary[key + ",to_server=%s" % event.get("flow", {}).get("to_server")] += 1
            elif etype == "stats":
                # only the counters that a replay decides on its own: what the
                # threads reached in host time (uptime, sweep rate, memuse,
                # averages) is not expected to agree
                stats = event.get("stats", {})
                for path in ("detect.alert", "flow.total", "tcp.sessions",
                        "decoder.pkts", "flow.wrk.flows_evicted_needs_work"):
                    node = stats
                    for part in path.split("."):
                        node = node.get(part, "-")
                        if not isinstance(node, dict):
                            break
                    summary["stat:" + path] += node if isinstance(node, int) else 0
    return summary


def main():
    if len(sys.argv) != 3:
        print("usage: compare.py <eve.json> <eve.json>")
        return 2
    a, b = summarize(sys.argv[1]), summarize(sys.argv[2])
    if a == b:
        print("IDENTICAL")
        return 0
    for key in sorted(set(a) | set(b)):
        if a.get(key, 0) != b.get(key, 0):
            print("DIFF %s: run1=%d run2=%d" % (key, a.get(key, 0), b.get(key, 0)))
    print("DIFFERENT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
