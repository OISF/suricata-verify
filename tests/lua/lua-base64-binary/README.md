Reproducer for lua/base64: LuaBase64Decode() knows the true decoded
length but returns the buffer with lua_pushstring(), so decoded output is
truncated at the first NUL byte. base64.decode("AA==") returns "" instead
of one NUL byte, and decoded binary payloads cannot round-trip.

The script asserts the decoded length and NUL position for all five
decode modes.

Ticket: #9055.
