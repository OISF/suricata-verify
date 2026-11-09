Reproducer for lua: userdata metatable forgery leads to FFI type
confusion. Userdata is validated only by metatable identity, so an
unsandboxed output script can set (debug.setmetatable) an md5 hasher's metatable to the
sha256 metatable; the methods then pass an SCMd5 pointer to the SCSha256
code and Box::from_raw it as an SCSha256 (ASAN: heap corruption, wrong
drop size).

A forged handle must be rejected with a clean Lua error.

Ticket: #9056.
