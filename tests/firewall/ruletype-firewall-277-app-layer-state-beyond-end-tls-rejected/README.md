# ruletype-firewall-277-app-layer-state-beyond-end-tls-rejected

`app-layer-state:>client_finished` compares against the tls completion state,
so mode `>` can never hold and the rule is rejected at load. 264 covers the
http1 equivalent; this pins the tls completion-state bound and the to-server
axis. Loaded with `-T`, fatal exit, stderr grep for the specific message.
