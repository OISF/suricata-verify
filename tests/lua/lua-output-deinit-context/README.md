# lua-output-deinit-context

An output script's deinit() runs from LuaLogThreadDeinit, which
SCTmThreadsSlotPacketLoopFinish calls after PacketPoolDestroy(). The Lua
registry still holds the last callback's Packet/PacketAlert/Flow/tx/File
pointers there, so a retained packet handle (packet:timestamp()) and
rule.get_rule() read freed memory: ASan reports heap-use-after-free in
LuaPacketTimestamp (util-lua-packetlib.c) and LuaRuleGetRule
(util-lua-rule.c). With the context slots cleared before deinit() both
fail closed; this test pins that result.

Uses the pcap of lua-output-http (6 HTTP alerts with the test rule).
