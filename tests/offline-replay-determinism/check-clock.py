#!/usr/bin/env python3
"""Fail if events are stamped before the packets they report on.

Flow events carry the clock of the moment they are written out, and the start and
end of the flow as seen in the file. In offline mode the clock is the oldest
packet timestamp of the workers: a worker that never got a packet holds it at the
start of the file, so the event then claims a flow that ran for 30 s ended at the
first second. Tolerance of 1 s, timezone agnostic.
"""

import datetime
import json
import re
import sys

TOLERANCE = datetime.timedelta(seconds=1)
# local time of the stamp, offset dropped: every event of one run carries the
# same one, and re.match beats fromisoformat on python before 3.11
STAMP = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")


def parse(stamp):
    m = STAMP.match(stamp)
    if m is None:
        raise ValueError("unparsable timestamp: %r" % (stamp,))
    parts = [int(x) if x else 0 for x in m.groups()]
    frac = m.group(7) or "0"
    parts[6] = int(frac[:6].ljust(6, "0"))
    return datetime.datetime(*parts)
behind = 0
checked = 0

with open(sys.argv[1]) as fh:
    for line in fh:
        event = json.loads(line)
        if event.get("event_type") != "flow":
            continue
        stamp = parse(event["timestamp"])
        end = parse(event["flow"]["end"])
        checked += 1
        if stamp + TOLERANCE < end:
            behind += 1
            print("BEHIND: flow %s stamped %s, last packet %s" % (event["flow_id"], stamp, end), file=sys.stderr)

if checked == 0:
    print("NO FLOW EVENTS", file=sys.stderr)
    sys.exit(1)
print("OK" if behind == 0 else "%d of %d flow events too early" % (behind, checked))
sys.exit(1 if behind else 0)
