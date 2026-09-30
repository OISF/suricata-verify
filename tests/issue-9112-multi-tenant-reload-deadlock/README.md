# Test Description

Test that the `reload-tenants` unix-socket command does not deadlock when
tenants share a detect loader thread.

Tenants are assigned to loader threads round-robin. With 14 tenants and
`multi-detect.loaders: 7`, each loader has two tenants. `reload-tenants` is
sent 20 times, and every reload must return `OK`.

Before the fix, `reload-tenants` holds the detect engine master lock while
queuing a reload task for each tenant, and a loader thread holds its own task
lock while it runs a task. The reload task needs the master lock. A loader that
starts its first task before its second task is queued blocks on the master
lock while holding its task lock, so the unix-socket thread can never queue the
second task. Suricata stops responding.

## How it works

`sc-driver.py` starts Suricata in unix-socket mode, sends the commands it reads
on stdin, and writes the replies to `sc.json`. If a command gets no reply
within `SC_TIMEOUT` seconds (default 30), it kills Suricata and exits
non-zero. A deadlock therefore fails the test rather than hanging the test run.
It does not need `suricatasc`.

A failing run shows this on stderr:

    error: no reply to 'reload-tenants' after 30s; Suricata is hung

## PCAP

None

## Related issues

- Ticket https://redmine.openinfosecfoundation.org/issues/9112
