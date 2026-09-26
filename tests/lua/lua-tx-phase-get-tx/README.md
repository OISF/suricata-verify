# lua-tx-phase-get-tx

Cover test for `suricata.dns.get_tx()` in the tx phase. A rule registered
with a tx hook (dns:request_complete) is inspected in the tx phase only
(app_inspect != NULL -> DetectRunTx), where the tx registry entry is
populated by the unconditional LuaExtensionsMatchSetup() write, so
get_tx() must return the live tx (here with the query name).

The ticket's stale-tx edge (a later inspection whose tx lookup fails and
must clear the registry) is unreachable via packet-level reproduction:
a lua rule is strictly either packet-phase or tx-phase (s->app_inspect
gating), so a single rule never sees a failed lookup after a successful
one. This pins the tx-phase contract instead. Identical behavior on the
unfixed and fixed trees (contract cover, green on both).
