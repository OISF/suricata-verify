Reproducer for util.thread_info() in the signature-hook context.

The lua keyword registered from an app-layer signature hook rule
(alert <proto>:<hook> ...) runs through the application-layer match
path only. Before the fix (Redmine 9079) only the packet match path set
the ThreadVars entry in the lua registry, so util.thread_info() raised
"internal error: no tv" from a hook rule and the script never matched:
0 alerts on unfixed code. With the registry entry set in
LuaExtensionsMatchSetup (all match paths) the call returns the table
and the alert fires exactly once.

The hook form of the rule is essential: a plain "alert ntp ..." rule
with an ntp keyword inspects through a path that does set the thread
vars pre-fix, and the test stays green on unfixed code (verified
against main 516636f).

Ticket: #9079.
