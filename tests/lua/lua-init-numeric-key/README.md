# lua-init-numeric-key

Both init() parsers (detect-lua.c and output-lua.c) read keys with
lua_tostring(), which turns a number key into a string in place. The next
lua_next() then cannot find the key and raises outside any pcall, so the
engine aborts: `return { false }` from a rule script's init() at rule
load, `{ true, type = "packet" }` from an output script's init() at
output setup. Fixed code skips the number keys; the rule loads and
alerts, the output script logs.
