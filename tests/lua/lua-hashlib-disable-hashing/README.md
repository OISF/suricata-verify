Reproducer for lua/hashlib: --disable-hashing sets g_disable_hashing and
is enforced by transforms, file hashing and JA3/JA4, but the Lua hashing
API never checks it. With the flag set a script can still compute
md5/sha1/sha256 on arbitrary data.

The script hashes with the flag set. Either documented behavior is
accepted (raise an error or return nil), but hashing must not work.

Ticket: #9059.
