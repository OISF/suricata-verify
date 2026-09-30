# ruletype-firewall-278-app-layer-state-start-state-smtp-rejected

`app-layer-state:<request_started` compares mode `<` against smtp's starting
to-server state, which can never hold, so the rule is rejected at load. 265
covers the http1 equivalent; this pins the smtp axis (the to-server table, not
the to-client one). Loaded with `-T`, fatal exit, stderr grep for the specific
message.
