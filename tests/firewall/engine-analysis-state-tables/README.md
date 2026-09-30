# engine-analysis-state-tables

Pins the application state-table names the firewall exposes per protocol.

A firewall-mode run writes `firewall.json` (the firewall analyzer) into the log
directory. Its `tables.<proto>` object holds one entry per application state,
keyed `app:<proto>:<state>` (for the HTTP/2-style parsers with an inner state
scope: `app:<proto>:<stream|global>:<state>`), each carrying the state's
policy and rules. A minimal `-T` run with a firewall `suricata.yaml` and
`--firewall-rules-exclusive firewall.rules` dumps the table for every
protocol, not only the ones with rules, so this test needs no pcap.

Each `shell` check loads `output/firewall.json` and compares the sorted state
keys of one protocol against the hard-coded expected list. A state rename,
addition or removal changes the list and fails the matching check with the
expected/actual diff. The lists were derived empirically from the current
binary; when the state machines change, update the corresponding list here
deliberately rather than deleting the check.

Covered protocols: `http` (the http1 parser), `tls`, `http2` (stream and
global scopes), `doh2` (stream and global scopes), `ssh`, `smtp`, `dns`,
`ntp`, `ftp` and `ftp-data`.

Notes:

- `http2` and `doh2` each expose both an inner `stream` and `global` scope, so
  their key lists contain both `app:<proto>:stream:*` and
  `app:<proto>:global:*`.
- `ssh` mixes `-` and `_` separators (`request-complete` vs `request_banner`);
  that is the current state naming and is pinned as-is.
