Regression test for lua: flowvar/flowint register() mutates the shared
DetectLuaData without synchronization (register per worker thread / per
match call) and registers the name before the 15 entry limit check, so
an over-limit call leaks a VarNameStore refcount/name entry that
DetectLuaFree never unregisters.

This test pins the supported behavior under --runmode autofp: the 15
flowints are registered by init() (rule load), match() can use them, and
an over-limit registration (script 2 registers 16) fails cleanly with
the engine staying alive.

The unsynchronized check-then-append race itself is only observable
under TSAN, and the VarNameStore refcount leak only with allocation
instrumentation; suricata-verify cannot assert either directly.

Ticket: #9074.
