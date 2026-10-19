# lua-luaxform-repeated-large-input

Repeated large inputs on the same Lua state: each call pushes a 200 KB
input and the script allocates a same-size copy. `string.upper`'s
`luaL_Buffer` growth peaks at 256 KB plus the previous 128 KB block, so
the call's working set is ~600 KB over the baseline. The input exemption
is the gross allocation between the `SCLuaSbResetBytesLimit` and the
`SCLuaSbUpdateBytesLimit`, so a GC step during the setup pushes
reclaiming the previous call's input (and copy) cannot shrink it and
pull the cap under the working set.

`security.lua.max-bytes=450000` is above the input but below the working
set: the fixed gross-exempt cap (baseline + 450 KB + 200 KB input)
clears the peak, while the old net-delta exemption re-bases on the
reclaimed live set and trips the memory limit on the repeated calls
(untransformed buffer, no alert). The test runs in single runmode so
all four sessions share one Lua state.

input.pcap: four HTTP/1.1 sessions, each a 200000-byte body carrying the
lowercase marker "marker42" (`python3 mkpcap.py input.pcap 4`).
