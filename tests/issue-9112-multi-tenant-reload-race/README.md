# Test Description

Test that `reload-tenants` does not corrupt the configuration tree when detect
loader threads reload tenants in parallel.

Before the fix, each loader thread loads its tenant's YAML into the global
configuration tree, which has no locking. A tenant's reload config is stored
under its original prefix (`multi-detect.<id>.reload.<n>` under
`multi-detect.<id>`). The first reload frees the tenant's original detect
engine, and that removes `multi-detect.<id>`. On the second reload, every
loader re-creates its `multi-detect.<id>` node under the shared `multi-detect`
node at the same time. An insert can be lost, and the reload fails with
`failed to load yaml` or `failed to properly setup yaml`. After that, later
`register-tenant` commands also fail, because the tree stays corrupted.

The race is timing dependent, so `commands.sh` repeats it 30 times. Each cycle:

- registers 8 new tenants,
- sends `reload-tenants` twice (the second reload is where the race happens),
- unregisters the 8 tenants.

All 540 commands must return `OK`.

`multi-detect.loaders` is 8 and no tenants are configured in YAML. Tenants are
assigned to loaders round-robin, so each tenant in a cycle gets its own loader.
This keeps the test from hitting the separate loader deadlock (see
`issue-9112-multi-tenant-reload-deadlock`).

## How it works

`sc-driver.py` starts Suricata in unix-socket mode, sends the commands it reads
on stdin, and writes the replies to `sc.json`. It stops at the first command
that does not return `OK`. If a command gets no reply within `SC_TIMEOUT`
seconds (default 30), it kills Suricata and exits non-zero. It does not need
`suricatasc`.

The commands come from `commands.sh`, not from inline shell in `test.yaml`.
`run.py` runs the `command` string through `string.Template` for the `cmdline`
file, and that rejects shell syntax such as `$(...)`.

A failing run shows this on stderr:

    error: 'reload-tenants' failed: reload tenants failed

## PCAP

None

## Related issues

- Ticket https://redmine.openinfosecfoundation.org/issues/9112
