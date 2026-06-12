# config-includes-glob-order

Verifies that a glob pattern in an `include:` directive expands to all matching
files and includes them in a deterministic (sorted) order.

`glob.yaml` includes `*-order.yaml`, which matches three drop-in files
(`01-order.yaml`, `50-order.yaml`, `99-order.yaml`). Each file defines its own
unique marker key (`glob-order-seen-NN`). Because `glob(3)` returns matches in
sorted (lexicographic) order, the files are merged in ascending numeric-prefix
order.

The test runs suricata against `glob.yaml` with `--dump-config` (via `command:`)
and asserts that:

- all three matched files were included (one unique marker key per file), and
- the marker keys appear in the dump output in sorted-filename order. The
  config tree preserves insertion order, so the position of each key in the
  output reflects the order the files were merged. No key is defined twice, so
  the test does not depend on duplicate-key override behavior.

What this test proves is narrow: sorted glob expansion. Real users care about
that property because it makes the common numbered drop-in convention
(`01-*.yaml` .. `99-*.yaml`, as in `conf.d`-style directories) predictable,
including the case where the same key is set in more than one drop-in. This
test does not exercise any of those override scenarios. It just pins the sort
order so it cannot silently regress (for example by expanding with
`GLOB_NOSORT` or a plain directory scan).

The glob config is kept in `glob.yaml` (not the default `suricata.yaml`) on
purpose: suricata-verify runs `suricata -c suricata.yaml --dump-config` during
test setup before the `min-version` check, so a glob `include:` in a shipped
`suricata.yaml` would break setup on Suricata builds without glob support.

Note: this test requires the `include:` glob support added in OISF/suricata
(#15574, Redmine #8427) and only passes against a Suricata build that has it.
