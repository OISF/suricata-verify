Reproducer for lua: the packet/flow/file/signature handles are raw
non-owning pointers cached by the script. The rule handle returned by
rule.get_rule() points at a Signature that is freed on rule reload
(SigFree), while output Lua states are not reinitialized, so a cached
handle dereferences freed memory (ASAN: heap-use-after-free in
LuaRuleGetSid read of s->id).

The paced pcap caches the handle from a pre-reload alert, SIGUSR2
reloads the rules mid-replay, and the next alerts dereference the stale
handle. The engine must survive to deinit.

Ticket: #9060.

Note: on a plain (non-ASAN) build the freed Signature memory often still
holds the right value, so this test only goes red with ASAN
(heap-use-after-free abort at the post-reload dereference); against plain
unfixed builds it acts as a survival check and passes.
