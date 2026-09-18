Reproducer for lua/flowint: set() casts luaL_checkinteger's signed 64
bit value to int and stores it in the uint32_t FlowVar value, so
set(2^32) stores 0 and set(2^63-1) stores 4294967295.

The output script calls set(2^32); either semantics is accepted
(rejected with an error, or stored exactly), but a silent truncation is
the bug.

Ticket: #9073.
